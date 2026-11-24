package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestProfileLoggingRedactsCredentialsWithoutChangingWireFormat(t *testing.T) {
	p := Profile{Token: "synthetic-token", UUID: "synthetic-uuid", AppUUID: "synthetic-app-uuid", Rules: []string{"private-rule.example"}}
	var out bytes.Buffer
	fmt.Fprintf(&out, "%v %+v %#v", p, p, p)
	slog.New(slog.NewJSONHandler(&out, nil)).Info("profile", "profile", p)
	for _, secret := range []string{p.Token, p.UUID, p.AppUUID, p.Rules[0]} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("profile log disclosed sensitive data")
		}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Profile
	if err = json.Unmarshal(raw, &decoded); err != nil || decoded.Token != p.Token || decoded.AppUUID != p.AppUUID {
		t.Fatal("redaction broke authenticated profile serialization")
	}
}
