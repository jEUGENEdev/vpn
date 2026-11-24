package store

import (
	"errors"
	"github.com/jEUGENEdev/vpn/internal/model"
	"path/filepath"
	"testing"
)

func TestViewsAndFailedUpdatesNeverChangeCommittedState(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.Update(func(s *State) error {
		s.Accounts["a"] = Account{Account: model.Account{ID: "a", Rules: []string{"example.com"}}, ApplicationRules: map[string]model.ApplicationRule{"x": {Decision: "trusted"}}}
		return nil
	})
	st.View(func(s State) error {
		a := s.Accounts["a"]
		a.Rules[0] = "changed"
		a.ApplicationRules["x"] = model.ApplicationRule{Decision: "denied"}
		delete(s.Accounts, "a")
		return nil
	})
	st.Update(func(s *State) error { delete(s.Accounts, "a"); return errors.New("rollback") })
	st.View(func(s State) error {
		a := s.Accounts["a"]
		if a.Rules[0] != "example.com" || a.ApplicationRules["x"].Decision != "trusted" {
			t.Fatal("view/update leaked into committed state")
		}
		return nil
	})
}

func TestNullCollectionsNormalize(t *testing.T) {
	st, err := decode([]byte(`{"Accounts":null,"Devices":null,"Requests":null,"Pairs":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if st.Accounts == nil || st.Devices == nil || st.Requests == nil || st.Pairs == nil {
		t.Fatal("null maps can panic on update")
	}
}

func TestFailedCommitKeepsCacheAndTokenIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Update(func(s *State) error {
		s.Accounts["a"] = Account{Account: model.Account{ID: "a"}}
		s.Devices["d"] = Device{Device: model.Device{ID: "d", AccountID: "a"}, Hash: "old"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Simulate a storage failure after a valid mutation, rather than callback error.
	if err = st.DB.Close(); err != nil {
		t.Fatal(err)
	}
	err = st.Update(func(s *State) error { d := s.Devices["d"]; d.Hash = "new"; s.Devices["d"] = d; return nil })
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("expected persistence error, got %v", err)
	}
	if _, _, ok, err := st.LookupDevice("old"); err != nil || !ok {
		t.Fatal("failed commit invalidated old token index")
	}
	if _, _, ok, _ := st.LookupDevice("new"); ok {
		t.Fatal("failed commit published new credentials")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, _, ok, err := reopened.LookupDevice("old"); err != nil || !ok {
		t.Fatal("durable token/index lost on reopen")
	}
}
