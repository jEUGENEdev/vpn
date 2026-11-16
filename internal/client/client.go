package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/events"
	"github.com/jEUGENEdev/vpn/internal/model"
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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Pinned  []string      `json:"pending_protection,omitempty"`
	API     string        `json:"api"`
	Pin     string        `json:"pin"`
	Profile model.Profile `json:"profile"`
}
type Client struct {
	mu        sync.RWMutex
	change    sync.Mutex
	config    Config
	dir       string
	http      *http.Client
	vpn       transport.Runtime
	Direct    *transport.Dialer
	DNS       *FakeDNS
	Events    *events.Center
	pending   map[string]time.Time
	dismissed map[string]bool
	active    map[io.Closer]string
	ready     bool
	status    string
	requests  []model.Request
	devices   []model.Device
	lastSync  time.Time
	tunnel    bool
	guard     bool
	vpnFailed bool
	closed    bool
}

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
	c := &Client{dir: dir, Direct: dialer, DNS: f, Events: events.New(), pending: map[string]time.Time{}, dismissed: map[string]bool{}, active: map[io.Closer]string{}, status: "setup", requests: []model.Request{}, devices: []model.Device{}}
	raw, e := os.ReadFile(filepath.Join(dir, "profile.json"))
	if e == nil {
		if e = json.Unmarshal(raw, &c.config); e != nil {
			f.Close()
			return nil, fmt.Errorf("повреждён профиль: %w", e)
		}
		if _, e = policy.Clean(append(c.config.Profile.Rules, c.config.Pinned...)); e != nil {
			f.Close()
			return nil, e
		}
		c.configureHTTP()
		c.status = "blocked"
	} else if !os.IsNotExist(e) {
		f.Close()
		return nil, e
	}
	return c, nil
}
func (c *Client) Close() {
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
	if c.config.Profile.Token != "" {
		return errors.New("устройство уже привязано; смена аккаунта требует удаления локального профиля администратором")
	}
	c.config.API = api
	c.config.Pin = pin
	c.configureHTTP()
	raw, _ := json.Marshal(c.config)
	return secure.Save(filepath.Join(c.dir, "profile.json"), raw)
}
func (c *Client) Auth(ctx context.Context, action string, data any) (any, error) {
	c.change.Lock()
	defer c.change.Unlock()
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
	var p model.Profile
	if e := c.request(ctx, "POST", path, data, &p); e != nil {
		return nil, e
	}
	if e := c.apply(p); e != nil {
		return nil, e
	}
	return map[string]bool{"ok": true}, nil
}
func (c *Client) apply(p model.Profile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	raw, _ := json.Marshal(next)
	if e = secure.Save(filepath.Join(c.dir, "profile.json"), raw); e != nil {
		c.ready = false
		return e
	}
	c.ready = false
	for flow := range c.active {
		delete(c.active, flow)
		flow.Close()
	}
	c.config = next
	if e = c.vpn.Apply(transport.ClientConfig(p)); e != nil {
		c.status = "blocked"
		return e
	}
	c.ready = p.Status == "active"
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
	c.change.Lock()
	defer c.change.Unlock()
	c.mu.RLock()
	logged := c.config.Profile.Token != ""
	c.mu.RUnlock()
	if !logged {
		return nil
	}
	var s syncResult
	if e := c.request(ctx, "GET", "/api/sync", nil, &s); e != nil {
		c.mu.Lock()
		c.ready = false
		c.status = "blocked"
		var apiError *APIError
		if errors.As(e, &apiError) && (apiError.Status == 401 || apiError.Status == 403) {
			c.status = "auth_required"
		}
		for flow, host := range c.active {
			if policy.Approved(c.effectiveRules(), host) {
				delete(c.active, flow)
				flow.Close()
			}
		}
		c.mu.Unlock()
		c.Events.Outage(time.Now(), "Связь с сервером потеряна. Одобренные адреса заблокированы; прямого обхода нет.")
		return e
	}
	c.mu.RLock()
	old := c.config.Profile
	ready := c.ready
	c.mu.RUnlock()
	if !ready || old.Revision != s.Profile.Revision || old.UUID != s.Profile.UUID {
		if e := c.apply(s.Profile); e != nil {
			return e
		}
	}
	c.mu.Lock()
	c.lastSync = time.Now()
	c.requests = s.Requests
	c.devices = s.Devices
	c.dismissed = map[string]bool{}
	// Keep local discoveries visible until the next GET confirms server storage.
	for _, request := range s.Requests {
		delete(c.pending, request.Target)
	}
	for _, target := range s.Dismissed {
		c.dismissed[target] = true
		delete(c.pending, target)
	}
	targets := []string{}
	for target := range c.pending {
		if policy.Approved(c.effectiveRules(), target) {
			delete(c.pending, target)
			continue
		}
		if len(targets) >= 100 {
			break
		}
		targets = append(targets, target)
	}
	c.mu.Unlock()
	if len(targets) > 0 {
		_ = c.request(ctx, "POST", "/api/discover", map[string]any{"targets": targets}, nil)
	}
	c.mu.RLock()
	vpnFailed := c.vpnFailed
	c.mu.RUnlock()
	if !vpnFailed {
		c.Events.Recovered(time.Now())
	}
	return nil
}
func (c *Client) Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		c.Sync(ctx)
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
	if c.ready && c.vpnFailed {
		status = "degraded"
	}
	requests := []model.Request{}
	seen := map[string]bool{}
	for _, request := range c.requests {
		seen[request.Target] = true
		if !request.Dismissed && !policy.Approved(c.effectiveRules(), request.Target) {
			requests = append(requests, request)
		}
	}
	for target, at := range c.pending {
		if !seen[target] && !c.dismissed[target] && !policy.Approved(c.effectiveRules(), target) {
			requests = append(requests, model.Request{Target: target, FirstSeen: at, LastSeen: at, Count: 1})
		}
	}
	return map[string]any{"status": status, "tunnel": c.tunnel, "guard": c.guard, "account_id": c.config.Profile.AccountID, "device_id": c.config.Profile.DeviceID, "server": c.config.API, "rules": c.effectiveRules(), "pending_protection": c.config.Pinned, "requests": requests, "devices": c.devices, "events": c.Events.List(), "last_sync": c.lastSync, "revision": c.config.Profile.Revision}
}
func (c *Client) Action(ctx context.Context, path string, data any) (any, error) {
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
				for flow, host := range c.active {
					if policy.Matches(target, host) {
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
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, errors.New("client stopped")
	}
	route := policy.Decide(c.effectiveRules(), target, c.ready)
	c.mu.RUnlock()
	addr := net.JoinHostPort(target, fmt.Sprint(port))
	if route == policy.Block {
		c.Events.Outage(time.Now(), "Запрос к одобренному адресу остановлен. Прямое соединение запрещено.")
		return nil, errors.New("protected destination is offline")
	}
	var conn net.Conn
	var err error
	if route == policy.VPN {
		conn, err = c.vpn.Dial(ctx, network, addr)
	} else {
		c.mu.Lock()
		if _, seen := c.pending[target]; !seen && !c.dismissed[target] && len(c.pending) < 1000 {
			c.pending[target] = time.Now()
		}
		c.mu.Unlock()
		conn, err = c.Direct.DialContext(ctx, network, addr)
	}
	if err != nil {
		if route == policy.Direct {
			c.Events.FailedDirect(time.Now(), target)
		} else {
			c.mu.Lock()
			c.vpnFailed = true
			c.mu.Unlock()
			c.Events.Outage(time.Now(), "Ошибка защищённого подключения. Повторим через VPN.")
		}
		return nil, err
	}
	c.mu.Lock()
	current := policy.Decide(c.effectiveRules(), target, c.ready)
	if current != route || c.closed {
		c.mu.Unlock()
		conn.Close()
		return nil, errors.New("policy changed during connection")
	}
	c.active[conn] = target
	c.mu.Unlock()
	return &tracked{Conn: conn, c: c}, nil
}

type tracked struct {
	net.Conn
	c        *Client
	received atomic.Bool
}

func (t *tracked) Close() error {
	t.c.mu.Lock()
	delete(t.c.active, t.Conn)
	t.c.mu.Unlock()
	return t.Conn.Close()
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
		t.received.Store(true)
		t.c.mu.Lock()
		target := t.c.active[t.Conn]
		protected := policy.Approved(t.c.effectiveRules(), target)
		recovered := protected && t.c.ready && t.c.vpnFailed
		if recovered {
			t.c.vpnFailed = false
		}
		t.c.mu.Unlock()
		if recovered {
			t.c.Events.Recovered(time.Now())
		}
	}
	if err != nil && (!errors.Is(err, io.EOF) || !t.received.Load()) {
		t.c.mu.Lock()
		target, active := t.c.active[t.Conn]
		protected := active && policy.Approved(t.c.effectiveRules(), target)
		if protected {
			t.c.vpnFailed = true
		}
		t.c.mu.Unlock()
		if protected {
			t.c.Events.Outage(time.Now(), "Защищённое соединение прервано. Прямого переключения нет.")
		} else if active {
			t.c.Events.FailedDirect(time.Now(), target)
		}
	}
	return n, err
}

func (c *Client) SetGuard(enabled bool) { c.mu.Lock(); c.guard = enabled; c.mu.Unlock() }

// Caller holds c.mu. Pending local approval is protective even before the API acknowledges it.
func (c *Client) effectiveRules() []string {
	return append(append([]string{}, c.config.Profile.Rules...), c.config.Pinned...)
}
