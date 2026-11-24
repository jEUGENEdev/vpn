package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jEUGENEdev/vpn/internal/model"
	"github.com/jEUGENEdev/vpn/internal/secure"
	"go.etcd.io/bbolt"
	"maps"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Persisted representations keep secret fields out of the public JSON models.
type Account struct {
	model.Account
	Hash    string `json:"password_hash,omitempty"` // Legacy only; password authentication is disabled.
	KeyHash string `json:"access_key_hash,omitempty"`

	ApplicationRules map[string]model.ApplicationRule `json:"application_rules,omitempty"`
}
type Device struct {
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	model.Device
	Secret    string `json:"vless"`
	AppSecret string `json:"app_vless,omitempty"`
	Hash      string `json:"token_hash"`
}
type Pair struct {
	DeviceID  string
	AccountID string
	Expires   time.Time
}
type State struct {
	BootstrapKey string `json:"bootstrap_key"`
	Accounts     map[string]Account
	Devices      map[string]Device
	Requests     map[string]model.Request
	Pairs        map[string]Pair
}

func Empty() State {
	return State{Accounts: map[string]Account{}, Devices: map[string]Device{}, Requests: map[string]model.Request{}, Pairs: map[string]Pair{}}
}

type Store struct {
	DB           *bbolt.DB
	mu           sync.RWMutex
	cache        State
	raw          []byte
	deviceByHash map[string]string
	closed       bool
}

// ErrStorage distinguishes persistence failures from callback validation errors.
// HTTP callers must not expose the wrapped implementation detail to clients.
var ErrStorage = errors.New("storage unavailable")

func storageError(err error) error { return fmt.Errorf("%w: %w", ErrStorage, err) }

func cloneAccount(a Account) Account {
	a.Rules = slices.Clone(a.Rules)
	a.ApplicationRules = maps.Clone(a.ApplicationRules)
	return a
}

func (v State) Clone() State {
	out := v
	out.Accounts = make(map[string]Account, len(v.Accounts))
	for id, a := range v.Accounts {
		out.Accounts[id] = cloneAccount(a)
	}
	out.Devices = maps.Clone(v.Devices)
	out.Requests = make(map[string]model.Request, len(v.Requests))
	for id, r := range v.Requests {
		r.FailedDevices = maps.Clone(r.FailedDevices)
		r.Sources = slices.Clone(r.Sources)
		out.Requests[id] = r
	}
	out.Pairs = maps.Clone(v.Pairs)
	return out
}

func (s *Store) reindex() {
	s.deviceByHash = make(map[string]string, len(s.cache.Devices))
	for id, d := range s.cache.Devices {
		if d.Hash != "" {
			s.deviceByHash[d.Hash] = id
		}
	}
}

// LookupDevice avoids decoding or copying the complete database for each bearer
// check. Authentication is still rechecked inside each mutating transaction.
func (s *Store) LookupDevice(hash string) (Device, Account, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Device{}, Account{}, false, storageError(bbolt.ErrDatabaseNotOpen)
	}
	id, ok := s.deviceByHash[hash]
	if !ok {
		return Device{}, Account{}, false, nil
	}
	d := s.cache.Devices[id]
	return d, cloneAccount(s.cache.Accounts[d.AccountID]), true, nil
}

func Open(path string) (*Store, error) {
	if err := secure.PrepareDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	db, e := bbolt.Open(path, 0600, &bbolt.Options{Timeout: time.Second, OpenFile: secure.OpenPrivateFile})
	if e != nil {
		return nil, e
	}
	s := &Store{DB: db, cache: Empty()}
	e = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("state"))
		if b == nil {
			return nil
		}
		s.raw = bytes.Clone(b.Get([]byte("v1")))
		var err error
		s.cache, err = decode(s.raw)
		return err
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	s.reindex()
	e = s.Update(func(*State) error { return nil })
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.DB.Close()
}
func decode(b []byte) (State, error) {
	v := Empty()
	if len(b) == 0 {
		return v, nil
	}
	err := json.Unmarshal(b, &v)
	if v.Accounts == nil {
		v.Accounts = map[string]Account{}
	}
	if v.Devices == nil {
		v.Devices = map[string]Device{}
	}
	if v.Requests == nil {
		v.Requests = map[string]model.Request{}
	}
	if v.Pairs == nil {
		v.Pairs = map[string]Pair{}
	}
	return v, err
}
func (s *Store) View(fn func(State) error) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return storageError(bbolt.ErrDatabaseNotOpen)
	}
	snapshot := s.cache.Clone()
	s.mu.RUnlock()
	return fn(snapshot)
}
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storageError(bbolt.ErrDatabaseNotOpen)
	}
	next := s.cache.Clone()
	if err := fn(&next); err != nil {
		return err
	}
	// Password authentication is disabled; do not retain obsolete hashes in new
	// snapshots (existing historical bbolt pages/backups require separate expiry).
	for id, a := range next.Accounts {
		a.Hash = ""
		a.PasswordHash = ""
		next.Accounts[id] = a
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return storageError(err)
	}
	if bytes.Equal(raw, s.raw) {
		return nil
	}
	err = s.DB.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("state"))
		if err != nil {
			return err
		}
		return b.Put([]byte("v1"), raw)
	})
	if err != nil {
		return storageError(err)
	}
	// Callers can retain aliases from callbacks, so the published cache owns a
	// separate snapshot. Failed commits never publish cache or token-index state.
	s.cache = next.Clone()
	s.raw = raw
	s.reindex()
	return nil
}
