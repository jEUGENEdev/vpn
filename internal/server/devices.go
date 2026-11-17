package server

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
)

type deviceChoice struct {
	Name      string `json:"name"`
	Platform  string `json:"platform"`
	DeviceID  string `json:"device_id,omitempty"`
	NewDevice bool   `json:"new_device,omitempty"`
}

// Only credentials or an unexpired pairing code may reach this function.
// Selection reveals no tokens and does not consume the pairing code.
func (s *Server) enrollChoice(account string, choice deviceChoice, pairHash string) (any, error) {
	return s.enrollChoiceAuthorized(choice, pairHash, func(*store.State) (string, error) { return account, nil })
}

// Authenticate and enroll in one transaction with profile/key/device revocation.
func (s *Server) enrollChoiceAuthorized(choice deviceChoice, pairHash string, authorize func(*store.State) (string, error)) (any, error) {
	if !validDevice("device", choice.Platform) || (choice.NewDevice && choice.DeviceID != "") {
		return nil, errors.New("некорректный выбор устройства")
	}
	s.change.Lock()
	defer s.change.Unlock()
	var result any
	changed := false
	err := s.Store.Update(func(st *store.State) error {
		account, err := authorize(st)
		if err != nil {
			return err
		}
		if pairHash != "" {
			pair, ok := st.Pairs[pairHash]
			if !ok || !time.Now().Before(pair.Expires) {
				return ErrForbidden
			}
			account = pair.AccountID
		}
		a, ok := st.Accounts[account]
		if !ok || a.Status != "active" {
			return ErrForbidden
		}
		var device store.Device
		if choice.DeviceID != "" {
			device, ok = st.Devices[choice.DeviceID]
			if ok && (device.AccountID != account || device.Platform != choice.Platform) {
				return ErrForbidden
			}
			if device.Revoked && time.Now().Before(device.Expires) {
				// A fresh account key can enroll again, but never resurrect revoked credentials.
				device = store.Device{}
			}
			// A deleted record is never resurrected. An explicit new login can
			// enroll this computer again with a fresh ID and fresh credentials.
		}
		name := strings.TrimSpace(choice.Name)
		if device.ID == "" && name == "" && !choice.NewDevice {
			devices := []model.Device{}
			for _, d := range st.Devices {
				if d.AccountID == account && d.Platform == choice.Platform && (!d.Revoked || !time.Now().Before(d.Expires)) {
					devices = append(devices, d.Device)
				}
			}
			sort.Slice(devices, func(i, j int) bool {
				if devices[i].Created.Equal(devices[j].Created) {
					return devices[i].ID < devices[j].ID
				}
				return devices[i].Created.Before(devices[j].Created)
			})
			result = map[string]any{"select_device": true, "devices": devices}
			return nil
		}
		if name == "" {
			name = device.Name
		}
		if name == "" {
			name = map[string]string{"android": "Android", "darwin": "Mac", "windows": "Windows", "linux": "Linux"}[choice.Platform] + " · " + secure.UUID()[:8]
		}
		if !validDevice(name, choice.Platform) {
			return errors.New("некорректное имя устройства")
		}
		count := 0
		for _, d := range st.Devices {
			if d.AccountID == account && d.ID != device.ID && !d.Revoked && time.Now().Before(d.Expires) {
				count++
			}
		}
		if count >= 20 {
			return errors.New("максимум 20 активных устройств")
		}
		if device.ID == "" {
			device.Device = model.Device{ID: secure.UUID(), AccountID: account, Platform: choice.Platform, Created: time.Now()}
		}
		device.Name = name
		device.Revoked = false
		device.Expires = time.Now().Add(90 * 24 * time.Hour)
		token := secure.Token()
		device.Hash, device.Secret = secure.Hash(token), secure.UUID()
		// Old per-application credentials must stop working too.
		if device.AppSecret != "" {
			device.AppSecret = secure.UUID()
		}
		st.Devices[device.ID] = device
		if pairHash != "" {
			delete(st.Pairs, pairHash)
		}
		result = s.profile(device, a, token)
		changed = true
		return nil
	})
	if err == nil && changed && s.Apply != nil {
		err = s.Store.View(s.Apply)
	}
	return result, err
}

func stillAuthorized(st *store.State, device store.Device) bool {
	current, ok := st.Devices[device.ID]
	return ok && secure.Equal(current.Hash, device.Hash) && !current.Revoked && time.Now().Before(current.Expires) && st.Accounts[current.AccountID].Status == "active"
}

func deleteDevice(st *store.State, device store.Device) {
	delete(st.Devices, device.ID)
	for key, pair := range st.Pairs {
		// Legacy codes have no issuer ID, so invalidate those for this account.
		if pair.AccountID == device.AccountID && (pair.DeviceID == "" || pair.DeviceID == device.ID) {
			delete(st.Pairs, key)
		}
	}
	for key, request := range st.Requests {
		if _, ok := request.FailedDevices[device.ID]; ok {
			delete(request.FailedDevices, device.ID)
			request.DirectFailed = len(request.FailedDevices) > 0
			st.Requests[key] = request
		}
	}
}
