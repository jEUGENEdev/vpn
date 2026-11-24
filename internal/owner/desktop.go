//go:build !android

package owner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/jEUGENEdev/vpn/internal/model"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type process struct {
	PID        int
	Name, Path string
}
type processLookup func(context.Context, string, netip.AddrPort, netip.AddrPort) (process, error)
type cachedIdentity struct {
	info model.ApplicationInfo
	file os.FileInfo
}
type Desktop struct {
	lookup processLookup
	closer io.Closer
	mu     sync.Mutex
	cache  map[string]cachedIdentity
}

func NewDesktop() (*Desktop, error) {
	lookup, closer, err := newProcessLookup()
	if err != nil {
		return nil, err
	}
	return &Desktop{lookup: lookup, closer: closer, cache: map[string]cachedIdentity{}}, nil
}
func (d *Desktop) Close() error {
	if d.closer != nil {
		return d.closer.Close()
	}
	return nil
}
func (d *Desktop) Lookup(ctx context.Context, network string, source, dest netip.AddrPort) (model.ApplicationInfo, error) {
	if !source.IsValid() || !dest.IsValid() || (network != "tcp" && network != "udp") {
		return model.ApplicationInfo{}, errors.New("invalid connection tuple")
	}
	p, err := d.lookup(ctx, network, source, dest)
	if err != nil || p.PID <= 0 || !filepath.IsAbs(p.Path) {
		return model.ApplicationInfo{}, errors.New("connection owner unavailable")
	}
	path, stat, err := executableFile(p.Path)
	if err != nil {
		return model.ApplicationInfo{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if cached, ok := d.cache[path]; ok && cached.file.Size() == stat.Size() && cached.file.ModTime().Equal(stat.ModTime()) && os.SameFile(cached.file, stat) {
		return cached.info, nil
	}
	info, err := executableIdentity(path, p.Name, stat)
	if err != nil {
		return model.ApplicationInfo{}, err
	}
	if len(d.cache) >= 512 {
		clear(d.cache)
	}
	d.cache[path] = cachedIdentity{info: info, file: stat}
	return info, nil
}

func executableFile(selected string) (string, os.FileInfo, error) {
	if !filepath.IsAbs(selected) {
		return "", nil, errors.New("требуется полный путь к приложению")
	}
	path, err := filepath.EvalSymlinks(selected)
	if err != nil {
		return "", nil, err
	}
	stat, err := os.Stat(path)
	if err != nil || !stat.Mode().IsRegular() {
		return "", nil, errors.New("исполняемый файл недоступен")
	}
	return path, stat, nil
}

func executableIdentity(path, name string, stat os.FileInfo) (model.ApplicationInfo, error) {
	// Trust belongs to the executable at this path and this version, never merely
	// to a process name. An updated/replaced binary needs a new decision.
	const maxSize = 512 << 20
	if stat.Size() > maxSize {
		return model.ApplicationInfo{}, errors.New("executable too large to identify")
	}
	f, err := os.Open(path)
	if err != nil {
		return model.ApplicationInfo{}, err
	}
	defer f.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(f, maxSize+1))
	if err != nil {
		return model.ApplicationInfo{}, err
	}
	after, err := f.Stat()
	if err != nil || size != stat.Size() || !os.SameFile(after, stat) || after.Size() != size || !after.ModTime().Equal(stat.ModTime()) {
		return model.ApplicationInfo{}, errors.New("executable changed during identification")
	}
	identityPath := path
	if runtime.GOOS == "windows" {
		identityPath = strings.ToLower(path)
	}
	id := sha256.Sum256([]byte(runtime.GOOS + "\n" + identityPath + "\n" + hex.EncodeToString(hash.Sum(nil))))
	if name == "" {
		name = filepath.Base(path)
	}
	return model.ApplicationInfo{ID: hex.EncodeToString(id[:]), Name: name, Path: path, Platform: runtime.GOOS}, nil
}
