package main

import (
	"context"
	"encoding/json"

	"github.com/jEUGENEdev/vpn/internal/secure"
)

type desktopOperator struct {
	token   string
	confirm func(context.Context, string) (bool, error)
	close   func()
}

// The token only enables a request for native consent. It is never a service
// credential or a settings grant. Publish it privately before granting read.
func writeOperatorToken(path string) (string, error) {
	token := secure.Token()
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return "", err
	}
	return token, secure.Save(path, body)
}
