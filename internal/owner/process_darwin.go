//go:build darwin

package owner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	xnet "github.com/xtls/xray-core/common/net"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"
)

func rawLookup(ctx context.Context, network string, source, dest netip.AddrPort) (process, error) {
	pid, name, path, err := xnet.FindProcess(network, source.Addr().String(), source.Port(), dest.Addr().String(), dest.Port())
	return process{pid, name, path}, err
}

type ownerQuery struct {
	Network             string
	Source, Destination netip.AddrPort
}
type ownerReply struct {
	Process process
	Error   string
}
type helper struct {
	mu            sync.Mutex
	input, output *os.File
	reader        *bufio.Reader
	cmd           *exec.Cmd
	closed        bool
}

func newProcessLookup() (processLookup, io.Closer, error) {
	if os.Geteuid() != 0 {
		return rawLookup, nil, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	input, childIn, err := makeInput()
	if err != nil {
		return nil, nil, err
	}
	childOut, output, err := makeInput()
	if err != nil {
		input.Close()
		childIn.Close()
		return nil, nil, err
	}
	cmd := exec.Command(exe, "--lookup-owner")
	cmd.Stdin = childIn
	cmd.Stdout = childOut
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		input.Close()
		childIn.Close()
		output.Close()
		childOut.Close()
		return nil, nil, err
	}
	childIn.Close()
	childOut.Close()
	h := &helper{input: input, output: output, reader: bufio.NewReaderSize(output, 8192), cmd: cmd}
	return h.lookup, h, nil
}

// Return writer then reader. Both channels are inherited anonymous pipes, not
// a privileged HTTP endpoint or a filesystem socket accessible to other apps.
func makeInput() (*os.File, *os.File, error) { r, w, e := os.Pipe(); return w, r, e }
func (h *helper) lookup(ctx context.Context, network string, source, dest netip.AddrPort) (process, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return process{}, errors.New("owner helper stopped")
	}
	deadline := time.Now().Add(2 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	h.input.SetWriteDeadline(deadline)
	h.output.SetReadDeadline(deadline)
	err := json.NewEncoder(h.input).Encode(ownerQuery{network, source, dest})
	if err != nil {
		return process{}, err
	}
	raw, err := h.reader.ReadSlice('\n')
	if err != nil {
		h.stop()
		return process{}, err
	}
	var reply ownerReply
	if json.Unmarshal(raw, &reply) != nil || reply.Error != "" {
		return process{}, errors.New("connection owner unavailable")
	}
	return reply.Process, nil
}
func (h *helper) stop() {
	if !h.closed {
		h.closed = true
		h.input.Close()
		h.output.Close()
		h.cmd.Process.Kill()
		h.cmd.Wait()
	}
}
func (h *helper) Close() error { h.mu.Lock(); defer h.mu.Unlock(); h.stop(); return nil }
func ServeHelper() error {
	if os.Geteuid() != 0 {
		return errors.New("owner helper needs service privileges")
	}
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		s, e := f.Stat()
		if e != nil || s.Mode()&os.ModeNamedPipe == 0 {
			return errors.New("owner helper requires inherited pipes")
		}
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 8192)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var q ownerQuery
		reply := ownerReply{}
		if json.Unmarshal(scanner.Bytes(), &q) != nil || !q.Source.IsValid() || !q.Destination.IsValid() || (q.Network != "tcp" && q.Network != "udp") {
			reply.Error = "invalid connection tuple"
		} else {
			p, e := rawLookup(context.Background(), q.Network, q.Source, q.Destination)
			reply.Process = p
			if e != nil {
				reply.Error = "owner unavailable"
			}
		}
		if e := encoder.Encode(reply); e != nil {
			return e
		}
	}
	return scanner.Err()
}
