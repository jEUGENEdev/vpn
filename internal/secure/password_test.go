package secure

import (
	"bytes"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"testing"
)

func TestAdminHashMigration(t *testing.T) {
	password := "synthetic admin password"
	hash, err := AdminHash(password)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(hash, []byte(password)) || bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
		t.Fatal("password not hashed")
	}
	same, err := AdminHash(string(hash))
	if err != nil || !bytes.Equal(hash, same) {
		t.Fatal("hash changed on redeploy", err)
	}
	for _, bad := range []string{"short", strings.Repeat("я", 40), " " + password, "$2b$broken"} {
		if _, err := AdminHash(bad); err == nil {
			t.Fatal("invalid admin credential accepted")
		}
	}
}
