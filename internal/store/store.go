package store

import (
	"encoding/json"
	"errors"
	"github.com/jEUGENEdev/vpn/internal/model"
	"go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"time"
)

// Persisted representations keep secret fields out of the public JSON models.
type Account struct {
	model.Account
	Hash string `json:"password_hash"`
}
type Device struct {
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
	Accounts map[string]Account
	Devices  map[string]Device
	Requests map[string]model.Request
	Pairs    map[string]Pair
}

func Empty() State {
	return State{map[string]Account{}, map[string]Device{}, map[string]model.Request{}, map[string]Pair{}}
}

type Store struct{ DB *bbolt.DB }

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, e := bbolt.Open(path, 0600, &bbolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	s := &Store{db}
	e = s.Update(func(*State) error { return nil })
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func decode(b []byte) (State, error) {
	v := Empty()
	if len(b) == 0 {
		return v, nil
	}
	err := json.Unmarshal(b, &v)
	return v, err
}
func (s *Store) View(fn func(State) error) error {
	return s.DB.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("state"))
		if b == nil {
			return errors.New("store uninitialized")
		}
		v, e := decode(b.Get([]byte("v1")))
		if e != nil {
			return e
		}
		return fn(v)
	})
}
func (s *Store) Update(fn func(*State) error) error {
	return s.DB.Update(func(tx *bbolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists([]byte("state"))
		if e != nil {
			return e
		}
		v, e := decode(b.Get([]byte("v1")))
		if e != nil {
			return e
		}
		if e = fn(&v); e != nil {
			return e
		}
		raw, e := json.Marshal(v)
		if e != nil {
			return e
		}
		return b.Put([]byte("v1"), raw)
	})
}
