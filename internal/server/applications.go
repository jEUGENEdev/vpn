package server

import (
	"net/http"

	"github.com/jEUGENEdev/vpn/internal/secure"
	"github.com/jEUGENEdev/vpn/internal/store"
)

// A second, device-scoped credential keeps app trust separate from the shared
// address allowlist. Names, paths and traffic history stay on the device.
func (s *Server) appVPN(w http.ResponseWriter, r *http.Request) {
	d, _, err := s.device(r)
	if err != nil {
		fail(w, 401, err)
		return
	}
	var input struct {
		Enabled bool `json:"enabled"`
	}
	if !body(w, r, &input) {
		return
	}
	err = s.mutation(func(st *store.State) error {
		current := st.Devices[d.ID]
		if !stillAuthorized(st, d) {
			return ErrForbidden
		}
		if input.Enabled && current.AppSecret == "" {
			current.AppSecret = secure.UUID()
		}
		if !input.Enabled {
			current.AppSecret = ""
		}
		st.Devices[d.ID] = current
		return nil
	})
	if err != nil {
		fail(w, 503, err)
		return
	}
	d, a, err := s.device(r)
	if err != nil {
		fail(w, 401, err)
		return
	}
	JSON(w, 200, s.profile(d, a, ""))
}
