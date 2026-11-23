package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/events"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/owner"
	"github.com/jEUGENEdev/vpn/internal/policy"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/transport"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Disabled     bool          `json:"vpn_disabled,omitempty"`
	TrafficMode  string        `json:"traffic_mode,omitempty"`
	BootstrapKey string        `json:"bootstrap_key,omitempty"`
	Pinned       []string      `json:"pending_protection,omitempty"`
	API          string        `json:"api"`
	Pin          string        `json:"pin"`
	Profile      model.Profile `json:"profile"`
}
type Client struct {
	identity     DeviceIdentity
	sent         map[string]time.Time
	resolved     map[string]time.Time
	mu           sync.RWMutex
	change       sync.Mutex
	config       Config
	dir          string
	http         *http.Client
	vpn          transport.Runtime
	appVPN       transport.Runtime
	apps         map[string]model.Application
	appInventory map[string]bool
	observed     map[string]*observation
	ownerLookup  owner.Lookup
	Direct       *transport.Dialer
	DNS          *FakeDNS
	Events       *events.Center
	pending      map[string]time.Time
	dismissed    map[string]bool
	active       map[io.Closer]activeFlow
	ready        bool
	status       string
	requests     []model.Request
	devices      []model.Device
	lastSync     time.Time
	syncPending  bool
	tunnel       bool
	guard        bool
	vpnFailed    bool
	vpnFailures  map[flowKey]time.Time
	routeEpoch   uint64
	closed       bool
	power        NetworkController
	powerPending bool
	powerError   string
	appScope     bool
	dnsSlots     chan struct{}

	policySyncError string
}

var ErrVPNUnavailable = errors.New("VPN недоступен; прямое подключение запрещено")
var ErrApplicationPermission = errors.New("приложению не разрешён VPN; защищённый адрес заблокирован")

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("%d: %s", e.Status, e.Message) }

func New(dir string, dialer *transport.Dialer) (*Client, error) {
	f, e := OpenDNS(dir)
	if e != nil {
		return nil, e
	}
	c := &Client{identity: nativeDeviceIdentity(), dir: dir, Direct: dialer, DNS: f, Events: events.New(), pending: map[string]time.Time{}, sent: map[string]time.Time{}, resolved: map[string]time.Time{}, dismissed: map[string]bool{}, active: map[io.Closer]activeFlow{}, apps: map[string]model.Application{}, observed: map[string]*observation{}, status: "setup", requests: []model.Request{}, devices: []model.Device{}}
	c.dnsSlots = make(chan struct{}, 64)
	raw, e := os.ReadFile(filepath.Join(dir, "profile.json"))
	if e == nil {
		if e = json.Unmarshal(raw, &c.config); e != nil {
			f.Close()
			return nil, fmt.Errorf("повреждён профиль: %w", e)
		}
		if !validTrafficMode(c.config.TrafficMode) {
			f.Close()
			return nil, errors.New("неизвестный режим трафика в профиле")
		}
		if _, e = policy.Clean(append(c.config.Profile.Rules, c.config.Pinned...)); e != nil {
			f.Close()
			return nil, e
		}
		c.configureHTTP()
		c.status = "blocked"
		if c.config.Profile.AccountID != "" && c.config.Profile.Token == "" {
			c.status = "auth_required"
		}
	} else if !os.IsNotExist(e) {
		f.Close()
		return nil, e
	}
	if e = c.loadApplications(); e != nil {
		f.Close()
		return nil, e
	}
	apps, e := c.mergeApplicationRulesLocked(c.config.Profile, nil)
	if e == nil && !reflect.DeepEqual(apps, c.apps) {
		e = c.saveApplications(apps)
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	c.apps = apps
	return c, nil
}
func (c *Client) Close() {
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.status = "stopped"
	for v := range c.active {
		delete(c.active, v)
		v.Close()
	}
	c.ready = false
	c.mu.Unlock()
	c.vpn.Close()
	c.appVPN.Close()
	c.DNS.Close()
}
func (c *Client) configureHTTP() {
	c.http = secure.HTTPClient(c.config.Pin)
	c.http.Transport.(*http.Transport).DialContext = c.Direct.DialContext
}
func Bootstrap(raw string) (string, string, error) {
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil || u.Scheme != "linevpn" || u.User != nil {
		return "", "", errors.New("нужен профиль linevpn://IP:8443?pin=…")
	}
	if _, e := netip.ParseAddr(u.Hostname()); e != nil {
		return "", "", errors.New("профиль должен содержать IP сервера")
	}
	if len(u.Query().Get("pin")) != 43 {
		return "", "", errors.New("неверный отпечаток сертификата")
	}
	if u.Port() == "" {
		return "", "", errors.New("в профиле отсутствует порт API")
	}
	return "https://" + u.Host, u.Query().Get("pin"), nil
}
func (c *Client) request(ctx context.Context, method, path string, in any, out any) error {
	c.mu.RLock()
	h := c.http
	cfg := c.config
	closed := c.closed
	c.mu.RUnlock()
	if closed {
		return errors.New("client stopped")
	}
	if h == nil {
		return errors.New("импортируйте профиль сервера")
	}
	var b []byte
	var e error
	if in != nil {
		b, e = json.Marshal(in)
		if e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, cfg.API+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.BootstrapKey != "" {
		req.Header.Set("X-LineVPN-Profile", cfg.BootstrapKey)
	}
	if cfg.Profile.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Profile.Token)
	}
	res, e := h.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		var v struct {
			Error string `json:"error"`
		}
		json.NewDecoder(io.LimitReader(res.Body, 32768)).Decode(&v)
		if v.Error == "" {
			v.Error = res.Status
		}
		return &APIError{res.StatusCode, v.Error}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
	}
	return nil
}
func (c *Client) SetBootstrap(uri string) error {
	api, pin, e := Bootstrap(uri)
	if e != nil {
		return e
	}
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("client stopped")
	}
	u, _ := url.Parse(strings.TrimSpace(uri))
	key := u.Query().Get("access")
	decoded, keyErr := base64.RawURLEncoding.DecodeString(key)
	if keyErr != nil || len(key) != 43 || len(decoded) != 32 {
		return errors.New("нужен новый профиль с ключом подключения: получите его в админке")
	}
	if (c.config.Profile.AccountID != "" || c.config.Profile.Token != "") && (api != c.config.API || pin != c.config.Pin) {
		return errors.New("связанное устройство может обновить профиль только того же сервера и сертификата")
	}
	next := c.config
	next.API, next.Pin, next.BootstrapKey = api, pin, key
	raw, _ := json.Marshal(next)
	if e = secure.Save(filepath.Join(c.dir, "profile.json"), raw); e != nil {
		return e
	}
	c.config = next
	c.configureHTTP()
	return nil
}
func (c *Client) Auth(ctx context.Context, action string, data any) (any, error) {
	c.change.Lock()
	defer c.change.Unlock()
	data, err := c.authDeviceData(data)
	if err != nil {
		return nil, err
	}
	if action == "register" {
		var out map[string]any
		e := c.request(ctx, "POST", "/api/register", data, &out)
		return out, e
	}
	path := "/api/login"
	if action == "pair/claim" {
		path = "/api/pair/claim"
	}
	c.mu.RLock()
	hasProfile := c.config.Profile.Token != ""
	c.mu.RUnlock()
	if hasProfile && action != "login" {
		return nil, errors.New("устройство уже связано с аккаунтом")
	}
	var response struct {
		model.Profile
		SelectDevice bool           `json:"select_device"`
		Devices      []model.Device `json:"devices"`
	}
	if e := c.request(ctx, "POST", path, data, &response); e != nil {
		return nil, e
	}
	if response.SelectDevice {
		return map[string]any{"select_device": true, "devices": response.Devices}, nil
	}
	if e := c.apply(response.Profile); e != nil {
		return nil, e
	}
	return map[string]bool{"ok": true}, nil
}
func (c *Client) apply(p model.Profile) error {
	return c.applyProfile(p, nil)
}

func (c *Client) applyProfile(p model.Profile, acknowledged []model.ApplicationRuleChange) (result error) {
	c.mu.Lock()
	prepared := false
	defer func() {
		c.mu.Unlock()
		if prepared {
			result = errors.Join(result, c.applyApplicationScope())
		}
	}()
	if c.closed {
		return errors.New("client stopped")
	}
	old := c.config.Profile
	if old.AccountID != "" && old.AccountID != p.AccountID {
		return errors.New("смена аккаунта запрещена")
	}
	if p.Revision < old.Revision {
		return errors.New("устаревшая политика")
	}
	rules, e := policy.Clean(p.Rules)
	if e != nil {
		return e
	}
	p.Rules = rules
	apps, e := c.mergeApplicationRulesLocked(p, acknowledged)
	if e != nil {
		return e
	}
	if p.Token == "" {
		p.Token = old.Token
	}
	next := c.config
	next.Profile = p
	next.Pinned = nil
	for _, r := range c.config.Pinned {
		if !policy.Approved(p.Rules, r) {
			next.Pinned = append(next.Pinned, r)
		}
	}
	defer func() {
		// Enforce newly protected routes even if applying the transport fails.
		// Unrelated direct traffic may continue; protected traffic may not.
		for flow, info := range c.active {
			if c.routeFlowLocked(info.key()) != info.Route {
				delete(c.active, flow)
				flow.Close()
			}
		}
	}()
	if c.appScope {
		mode := c.trafficModeLocked()
		c.mu.Unlock()
		e = c.prepareApplicationScope(mode, apps)
		c.mu.Lock()
		if e != nil {
			return e
		}
		prepared = true
	}
	raw, _ := json.Marshal(next)
	if e = secure.Save(filepath.Join(c.dir, "profile.json"), raw); e != nil {
		c.ready = false
		return e
	}
	if !reflect.DeepEqual(apps, c.apps) {
		if e = c.saveApplications(apps); e != nil {
			c.ready = false
			return e
		}
	}
	c.ready = false
	vpnChanged := !reflect.DeepEqual(transport.ClientConfig(old), transport.ClientConfig(p))
	appChanged := vpnChanged || old.AppUUID != p.AppUUID
	// Close affected transports before replacement, so deliberate policy
	// changes are not mistaken for network failures by tracked connections.
	for flow, info := range c.active {
		if (info.Route == policy.VPN && vpnChanged) || (info.Route == policy.AppVPN && appChanged) {
			delete(c.active, flow)
			flow.Close()
		}
	}
	if vpnChanged || appChanged {
		clear(c.vpnFailures)
		c.vpnFailed = false
	}
	c.config = next
	c.routeEpoch++
	c.apps = apps
	if next.Disabled {
		c.vpn.Close()
		c.appVPN.Close()
		c.status = "disabled"
		c.lastSync = time.Now()
		return nil
	}
	if e = c.vpn.Apply(transport.ClientConfig(p)); e != nil {
		c.status = "blocked"
		return e
	}
	if p.AppUUID != "" {
		appProfile := p
		appProfile.UUID = p.AppUUID
		if e = c.appVPN.Apply(transport.ClientConfig(appProfile)); e != nil {
			c.status = "blocked"
			return e
		}
	} else {
		c.appVPN.Close()
	}
	c.ready = p.Status == "active"
	if c.ready {
		for flow, info := range c.active {
			if c.routeFlowLocked(info.key()) != info.Route {
				delete(c.active, flow)
				flow.Close()
			}
		}
	}
	c.status = "ready"
	c.lastSync = time.Now()
	return nil
}

type syncResult struct {
	Profile   model.Profile   `json:"profile"`
	Requests  []model.Request `json:"requests"`
	Dismissed []string        `json:"dismissed"`
	Devices   []model.Device  `json:"devices"`
}

func (c *Client) Sync(ctx context.Context) error {
	return c.sync(ctx, false)
}

func (c *Client) sync(ctx context.Context, background bool) error {
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.RLock()
	logged := c.config.Profile.Token != "" && !(background && c.config.Disabled && c.pendingPolicyCountLocked() == 0) && !c.powerPending && c.powerError == ""
	c.mu.RUnlock()
	if !logged {
		return nil
	}
	var s syncResult
	if e := c.request(ctx, "GET", "/api/sync", nil, &s); e != nil {
		var apiError *APIError
		revoked := errors.As(e, &apiError) && (apiError.Status == 401 || apiError.Status == 403)
		if ctx.Err() != nil && !revoked {
			return e
		}
		c.mu.Lock()
		c.syncPending = true
		if revoked {
			if saveErr := c.forgetAccessLocked(); saveErr != nil {
				e = fmt.Errorf("доступ отозван; не удалось очистить локальные ключи: %w", saveErr)
			}
		}
		// A timeout/5xx from the control API says nothing about live VPN
		// streams. Only an explicit access rejection invalidates credentials.
		c.mu.Unlock()
		if revoked && !c.disabled() {
			c.Events.Outage(time.Now(), "Доступ к VPN отозван или истёк. Разрешённые адреса и доверенные приложения заблокированы до восстановления доступа или выключения VPN.")
		}
		return e
	}
	c.mu.RLock()
	old := c.config.Profile
	ready := c.ready
	disabled := c.config.Disabled
	c.mu.RUnlock()
	// Server transport settings can change without changing the account's
	// policy revision (for example an SNI, REALITY key or XHTTP path change).
	// Compare the same generated configuration that applyProfile installs.
	transportChanged := !reflect.DeepEqual(transport.ClientConfig(old), transport.ClientConfig(s.Profile))
	if (!ready && !disabled && s.Profile.Status == "active") ||
		old.Status != s.Profile.Status || old.Revision != s.Profile.Revision ||
		transportChanged || old.AppUUID != s.Profile.AppUUID || old.Login != s.Profile.Login ||
		!reflect.DeepEqual(old.ApplicationRules, s.Profile.ApplicationRules) || len(c.pendingPins()) > 0 {
		if e := c.apply(s.Profile); e != nil {
			return e
		}
	}
	c.mu.Lock()
	c.syncPending = false
	c.lastSync = time.Now()
	c.requests = s.Requests
	c.devices = s.Devices
	c.dismissed = map[string]bool{}
	// Keep local discoveries visible until the next GET confirms server storage.
	for _, request := range s.Requests {
		if request.DirectFailed && c.sent[request.Target] == c.pending[request.Target] {
			delete(c.pending, request.Target)
			delete(c.sent, request.Target)
		}
	}
	for _, target := range s.Dismissed {
		c.dismissed[target] = true
		delete(c.pending, target)
	}
	targets := []string{}
	stamps := map[string]time.Time{}
	recovered := map[string]time.Time{}
	for target, at := range c.resolved {
		if len(recovered) < 100 {
			recovered[target] = at
		}
	}
	for target := range c.pending {
		if o := c.observed[target]; o == nil || !o.Failed || time.Since(o.LastFailure) >= 30*time.Minute {
			delete(c.pending, target)
			delete(c.sent, target)
			continue
		}
		if policy.Approved(c.effectiveRules(), target) || c.isDismissedLocked(target) {
			delete(c.pending, target)
			continue
		}
		if len(targets) >= 100 {
			break
		}
		targets = append(targets, target)
		stamps[target] = c.pending[target]
	}
	c.mu.Unlock()
	if len(targets) > 0 || len(recovered) > 0 {
		cleared := []string{}
		for target := range recovered {
			cleared = append(cleared, target)
		}
		if c.request(ctx, "POST", "/api/discover", map[string]any{"failed_targets": targets, "resolved_targets": cleared}, nil) == nil {
			c.mu.Lock()
			for target, at := range stamps {
				if c.pending[target] == at {
					c.sent[target] = at
				}
			}
			for target, at := range recovered {
				if c.resolved[target] == at {
					delete(c.resolved, target)
				}
			}
			c.mu.Unlock()
		}
	}
	c.mu.RLock()
	vpnFailed := c.vpnFailed
	c.mu.RUnlock()
	if !vpnFailed && !disabled && ready {
		c.Events.Recovered(time.Now())
	}
	policyErr := c.syncSavedPolicy(ctx)
	if err := c.ensureApplicationTunnel(ctx); err != nil {
		return err
	}
	return policyErr
}
func (c *Client) Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		c.sync(ctx, true)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (c *Client) SetTunnel(ready bool) { c.mu.Lock(); c.tunnel = ready; c.mu.Unlock() }
func (c *Client) State() any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	status := c.status
	appPending := c.needsApplicationTunnelLocked() && c.config.Profile.AppUUID == ""
	if c.ready && (c.vpnFailed || appPending) {
		status = "degraded"
	}
	if c.config.Disabled {
		status = "disabled"
	}
	if c.config.Disabled && c.guard && !c.tunnel {
		status = "system_blocked"
	}
	if c.powerError != "" {
		status = "network_error"
	}
	if c.powerPending {
		status = "switching"
	}
	requests := c.requestsLocked()
	apps, pendingApps := c.applicationSnapshotLocked()
	rules := c.effectiveRules()
	return map[string]any{"native_app_scope": c.appScope, "traffic_mode": c.trafficModeLocked(), "policy_sync_pending": c.pendingPolicyCountLocked(), "policy_sync_error": c.policySyncError, "vpn_issues": c.vpnIssuesLocked(), "sync_pending": c.syncPending, "device": c.identity, "status": status, "vpn_enabled": !c.config.Disabled, "fail_closed": true, "protection_blocked": !c.config.Disabled && (!c.ready || c.vpnFailed || appPending || !c.tunnel || c.powerError != ""), "partial_outage": !c.config.Disabled && c.ready && c.tunnel && (c.vpnFailed || appPending), "power_transition": c.powerPending, "power_error": c.powerError, "auth_required": c.status == "auth_required" || (c.config.Profile.AccountID != "" && c.config.Profile.Token == ""), "login": c.config.Profile.Login, "tunnel": c.tunnel, "guard": c.guard, "account_id": c.config.Profile.AccountID, "device_id": c.config.Profile.DeviceID, "server": c.config.API, "rules": rules, "rule_sources": c.ruleSourcesLocked(rules), "pending_protection": c.config.Pinned, "requests": requests, "request_groups": groupRequests(requests), "applications": apps, "pending_applications": pendingApps, "app_tunnel": c.ready && c.config.Profile.AppUUID != "", "attribution_available": c.ownerLookup != nil, "devices": c.devices, "events": c.Events.List(), "last_sync": c.lastSync, "revision": c.config.Profile.Revision}
}
func (c *Client) Action(ctx context.Context, path string, data any) (any, error) {
	if path == "traffic-mode" {
		fields, _ := data.(map[string]any)
		mode, _ := fields["mode"].(string)
		if mode != TrafficSelective && mode != TrafficAll {
			return nil, errors.New("выберите selective или all")
		}
		if err := c.SetTrafficMode(mode); err != nil {
			return nil, err
		}
		// Persist protection first. A failed/offline sync cannot restore direct.
		_ = c.Sync(ctx)
		return c.State(), nil
	}
	if path == "vpn" {
		fields, ok := data.(map[string]any)
		if !ok {
			return nil, errors.New("укажите enabled")
		}
		enabled, ok := fields["enabled"].(bool)
		if !ok {
			return nil, errors.New("укажите enabled: true или false")
		}
		if !enabled && fields["confirm"] != true {
			return nil, errors.New("подтвердите прямое подключение без VPN")
		}
		if err := c.SetVPNEnabled(enabled); err != nil {
			return nil, err
		}
		// Keep the user's intent; unavailable protected routes remain blocked.
		if enabled {
			_ = c.Sync(ctx)
		}
		return c.State(), nil
	}
	if path == "access-key/rotate" {
		var out map[string]string
		if err := c.request(ctx, "POST", "/api/access-key/rotate", data, &out); err != nil {
			return nil, err
		}
		_ = c.Sync(ctx) // Our old device session is now revoked. Preserve the one-time key response.
		return out, nil
	}
	if path == "applications" {
		return c.applicationAction(ctx, data)
	}
	if path == "rules" {
		if fields, ok := data.(map[string]any); ok && fields["action"] == "approve" {
			target, _ := fields["target"].(string)
			target, e := policy.Normalize(target)
			if e != nil {
				return nil, e
			}
			c.change.Lock()
			c.mu.Lock()
			next := c.config
			next.Pinned = append(append([]string{}, next.Pinned...), target)
			next.Pinned, _ = policy.Clean(next.Pinned)
			raw, _ := json.Marshal(next)
			e = secure.Save(filepath.Join(c.dir, "profile.json"), raw)
			if e == nil {
				c.config = next
				c.routeEpoch++
				for flow, info := range c.active {
					if policy.Matches(target, info.Target) {
						delete(c.active, flow)
						flow.Close()
					}
				}
			}
			c.mu.Unlock()
			c.change.Unlock()
			if e != nil {
				return nil, e
			}
		}
	}

	allowed := map[string]bool{"rules": true, "dismiss": true, "pair": true, "revoke": true}
	if !allowed[path] {
		return nil, errors.New("unknown action")
	}
	var out any
	e := c.request(ctx, "POST", "/api/"+path, data, &out)
	if e == nil && path == "rules" {
		if fields, ok := data.(map[string]any); ok && fields["action"] == "remove" {
			target, _ := fields["target"].(string)
			c.change.Lock()
			c.mu.Lock()
			next := c.config
			next.Pinned = nil
			for _, r := range c.config.Pinned {
				if r != target {
					next.Pinned = append(next.Pinned, r)
				}
			}
			raw, _ := json.Marshal(next)
			if err := secure.Save(filepath.Join(c.dir, "profile.json"), raw); err == nil {
				c.config = next
			} else {
				e = err
			}
			c.mu.Unlock()
			c.change.Unlock()
		}
	}
	if e == nil && path == "revoke" {
		if fields, ok := data.(map[string]any); ok {
			id, _ := fields["id"].(string)
			c.change.Lock()
			c.mu.Lock()
			kept := make([]model.Device, 0, len(c.devices))
			for _, device := range c.devices {
				if device.ID != id {
					kept = append(kept, device)
				}
			}
			c.devices = kept
			if id == c.config.Profile.DeviceID {
				saveErr := c.forgetAccessLocked()
				c.mu.Unlock()
				c.change.Unlock()
				if saveErr != nil {
					return out, fmt.Errorf("устройство удалено на сервере; не удалось очистить локальные ключи: %w", saveErr)
				}
				return out, nil
			}
			c.mu.Unlock()
			c.change.Unlock()
		}
		// The deletion already committed. A later sync failure is not a failed deletion.
		_ = c.Sync(ctx)
		return out, nil
	}
	if e == nil {
		e = c.Sync(ctx)
	}
	return out, e
}
func (c *Client) target(ip netip.Addr) (string, error) {
	name, fake := c.DNS.Lookup(ip)
	if fake && name == "" {
		return "", errors.New("неизвестный адрес DNS: прямое подключение запрещено")
	}
	return name, nil
}
func (c *Client) Dial(ctx context.Context, network, target string, port uint16) (net.Conn, error) {
	return c.dialApplication(ctx, network, target, port, model.ApplicationInfo{})
}
func (c *Client) dialApplication(ctx context.Context, network, target string, port uint16, app model.ApplicationInfo) (net.Conn, error) {
	return c.dialAtEpoch(ctx, network, target, port, app, nil)
}

// A DNS request selected in full mode must not become a direct query if the
// user changes modes before its upstream connection is opened.
func (c *Client) dialAtEpoch(ctx context.Context, network, target string, port uint16, app model.ApplicationInfo, requiredEpoch *uint64) (net.Conn, error) {
	if !validApplication(app) {
		app = model.ApplicationInfo{}
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("client stopped")
	}
	if requiredEpoch != nil && c.routeEpoch != *requiredEpoch {
		c.mu.Unlock()
		return nil, errors.New("policy changed before connection")
	}
	c.observeLocked(target, app, time.Now())
	key := flowKey{Target: target, AppID: app.ID, Network: network, Port: port}
	route := c.routeFlowLocked(key)
	protected := c.wantsVPNLocked(target, app.ID)
	missingConsent := !c.config.Disabled && c.config.TrafficMode != TrafficAll && policy.Approved(c.effectiveRules(), target) && !c.applicationAllowedLocked(app.ID)
	epoch := c.routeEpoch
	c.mu.Unlock()
	addr := net.JoinHostPort(target, fmt.Sprint(port))
	if route == policy.Block {
		if missingConsent {
			return nil, ErrApplicationPermission
		}
		if protected {
			c.Events.ConnectionOutage(time.Now(), "VPN недоступен. Прямое подключение запрещено; ждём восстановления VPN или ручного выключения.", target, app)
			return nil, ErrVPNUnavailable
		}
		return nil, errors.New("invalid destination")
	}
	var conn net.Conn
	var err error
	if route == policy.VPN {
		conn, err = c.vpn.Dial(ctx, network, addr)
	} else if route == policy.AppVPN {
		conn, err = c.appVPN.Dial(ctx, network, addr)
	} else {
		conn, err = c.Direct.DialContext(ctx, network, addr)
	}
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil && route != policy.Direct {
		c.mu.Lock()
		if c.closed || c.routeEpoch != epoch {
			c.mu.Unlock()
			return nil, errors.New("policy changed during connection")
		}
		c.failVPNLocked(key)
		c.mu.Unlock()
		c.Events.ConnectionOutage(time.Now(), "Ошибка VPN. Прямое подключение запрещено. Повторное соединение использует VPN.", target, app)
		return nil, fmt.Errorf("%w: %v", ErrVPNUnavailable, err)
	}
	if err != nil {
		if route == policy.Direct {
			if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
				c.directFailure(target, app.ID, time.Now())
			}
		}
		return nil, err
	}
	c.mu.Lock()
	current := c.routeFlowLocked(key)
	if current != route || c.closed || c.routeEpoch != epoch {
		c.mu.Unlock()
		conn.Close()
		return nil, errors.New("policy changed during connection")
	}
	c.active[conn] = activeFlow{Target: target, AppID: app.ID, Network: network, Port: port, Route: route}
	c.mu.Unlock()
	return &tracked{Conn: conn, c: c, source: app}, nil
}

type tracked struct {
	net.Conn
	c               *Client
	source          model.ApplicationInfo
	received        atomic.Bool
	failureReported atomic.Bool
	closed          atomic.Bool
	responseOnce    sync.Once
	responseTimer   atomic.Pointer[time.Timer]
	writes          atomic.Uint64
	checkedWrites   atomic.Uint64
}

const firstResponseTimeout = 20 * time.Second

func (t *tracked) Close() error {
	t.closed.Store(true)
	t.stopResponseTimer()
	t.c.mu.Lock()
	delete(t.c.active, t.Conn)
	t.c.mu.Unlock()
	return t.Conn.Close()
}

func (t *tracked) stopResponseTimer() {
	if timer := t.responseTimer.Load(); timer != nil {
		timer.Stop()
	}
}
func (t *tracked) reportDirectFailure() {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	flow, active := t.c.active[t.Conn]
	if !active || flow.Route != policy.Direct || t.closed.Load() || t.received.Load() || t.failureReported.Swap(true) {
		return
	}
	t.c.directFailureLocked(flow.Target, flow.AppID, time.Now())
}

func (t *tracked) reportVPNFailure(message string) {
	t.c.mu.Lock()
	flow, active := t.c.active[t.Conn]
	if !active || flow.Route == policy.Direct || t.closed.Load() || t.c.closed || t.failureReported.Swap(true) {
		t.c.mu.Unlock()
		return
	}
	t.c.failVPNLocked(flow.key())
	t.c.mu.Unlock()
	t.c.Events.ConnectionOutage(time.Now(), message+" Повторная попытка также использует VPN; прямое подключение запрещено.", flow.Target, t.source)
}

func (t *tracked) reportResponseTimeout() {
	t.c.mu.Lock()
	flow, active := t.c.active[t.Conn]
	if !active || t.closed.Load() || t.received.Load() {
		t.c.mu.Unlock()
		return
	}
	if flow.Route == policy.Direct {
		if flow.Network == "udp" {
			// A media socket can retry indefinitely without creating a new NAT
			// flow. Count a new unanswered window only if more data was sent;
			// a single datagram must never manufacture repeated failures.
			writes := t.writes.Load()
			previous := t.checkedWrites.Swap(writes)
			if writes > previous && (!t.failureReported.Swap(true) || previous > 0) {
				t.c.directFailureLocked(flow.Target, flow.AppID, time.Now())
			}
			t.c.mu.Unlock()
			t.startResponseTimer()
			return
		}
		t.c.mu.Unlock()
		t.reportDirectFailure()
		return
	}
	// TCP uploads and long-running requests can also be silent. The VPN is
	// not an application-protocol parser and cannot impose a response limit.
	t.c.mu.Unlock()
}

func (t *tracked) startResponseTimer() {
	t.c.mu.RLock()
	flow, active := t.c.active[t.Conn]
	t.c.mu.RUnlock()
	if !active || t.received.Load() || t.closed.Load() || flow.Route != policy.Direct {
		return
	}
	timer := time.AfterFunc(firstResponseTimeout, t.reportResponseTimeout)
	t.responseTimer.Store(timer)
	if t.received.Load() || t.closed.Load() {
		timer.Stop()
	}
}

func (t *tracked) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		t.writes.Add(1)
		// Direct flows stay open, including while unanswered UDP retries are
		// observed. A late reply can still clear the suggestion on this socket.
		t.responseOnce.Do(t.startResponseTimer)
	}
	if err != nil {
		t.reportDirectFailure()
		if !localConnectionEnd(err) {
			t.reportVPNFailure("Ошибка отправки данных через VPN.")
		}
	}
	return n, err
}

func (t *tracked) CloseWrite() error {
	if c, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return t.Close()
}

func (t *tracked) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		if !t.received.Swap(true) {
			t.stopResponseTimer()
			t.c.mu.RLock()
			flow, active := t.c.active[t.Conn]
			t.c.mu.RUnlock()
			if active && flow.Route == policy.Direct {
				t.c.directRecovered(flow.Target, flow.AppID, time.Now())
			}
		}
		t.c.mu.Lock()
		info, active := t.c.active[t.Conn]
		protected := active && info.Route != policy.Direct
		recovered := protected && t.c.ready && t.c.vpnFailed
		if recovered {
			t.c.recoverVPNLocked(info.key())
		}
		fullyRecovered := recovered && !t.c.vpnFailed
		t.c.mu.Unlock()
		if fullyRecovered {
			t.c.Events.ConnectionRecovered(time.Now(), info.Target, t.source)
		}
	}
	// Local deadlines, cancellation and an unused/finished TCP stream are
	// normal lifecycle events. Xray can return EOF on an asynchronous dial
	// failure, so an unanswered stream that actually sent data still counts.
	if err != nil && !localConnectionEnd(err) && !t.closed.Load() {
		t.c.mu.RLock()
		info, active := t.c.active[t.Conn]
		protected := active && info.Route != policy.Direct
		t.c.mu.RUnlock()
		if protected && (!errors.Is(err, io.EOF) || (!t.received.Load() && t.writes.Load() > 0)) {
			t.reportVPNFailure("Ошибка чтения данных через VPN.")
		} else if active && !protected {
			t.reportDirectFailure()
		}
	}
	return n, err
}

func localConnectionEnd(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}

func (c *Client) SetGuard(enabled bool) { c.mu.Lock(); c.guard = enabled; c.mu.Unlock() }

// Caller holds c.mu. Pending local approval is protective even before the API acknowledges it.
func (c *Client) effectiveRules() []string {
	return append(append([]string{}, c.config.Profile.Rules...), c.config.Pinned...)
}
