package platform

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type dnsSession struct {
	input io.WriteCloser
	done  chan error
	once  sync.Once
	err   error
}

func (s *dnsSession) Close() error {
	s.once.Do(func() {
		// EOF ends scutil and configd removes this session's temporary key.
		// Unlike signalling its root process, closing our pipe works after setuid.
		_ = s.input.Close()
		select {
		case s.err = <-s.done:
		case <-time.After(3 * time.Second):
			s.err = errors.New("temporary DNS session did not close")
		}
	})
	return s.err
}

func startTunnelDNS() (io.Closer, error) {
	key := fmt.Sprintf("State:/Network/Service/dev.linevpn.%d/DNS", os.Getpid())
	cmd := exec.Command("/usr/sbin/scutil")
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err = cmd.Start(); err != nil {
		input.Close()
		return nil, err
	}
	s := &dnsSession{input: input, done: make(chan error, 1)}
	go func() { s.done <- cmd.Wait() }()
	// SCDynamicStoreAddTemporaryValue is scoped to the scutil connection.
	// The pipe has no other writer: even SIGKILL of the agent produces EOF.
	// Do not set Setup:/ keys or physical-interface DNS preferences.
	script := "d.init\nd.add ServerAddresses * " + tunnelDNS + "\nd.add SupplementalMatchDomains * \"\"\nd.add SupplementalMatchDomainsNoSearch # 1\nd.add SupplementalMatchOrders * # 1\nadd " + key + " temporary\n"
	if _, err = io.WriteString(input, script); err != nil {
		s.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = exec.CommandContext(ctx, "/usr/sbin/scutil", "-w", key, "-t", "3").Run(); err != nil {
		s.Close()
		return nil, fmt.Errorf("temporary DNS registration: %w", err)
	}
	check := exec.CommandContext(ctx, "/usr/sbin/scutil")
	check.Stdin = strings.NewReader("show " + key + "\n")
	output, err := check.CombinedOutput()
	if err != nil || !strings.Contains(string(output), tunnelDNS) || !strings.Contains(string(output), "SupplementalMatchDomains") {
		s.Close()
		return nil, fmt.Errorf("temporary DNS not registered: %s (%v)", output, err)
	}
	return s, nil
}
