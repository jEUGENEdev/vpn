//go:build !android

package owner

import (
	"context"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jEUGENEdev/vpn/internal/model"
)

// IdentifySelection runs as the interactive user. The service never opens a
// user-supplied path, and the selected program is never launched.
func IdentifySelection(ctx context.Context, selected string) (model.ApplicationInfo, error) {
	var zero model.ApplicationInfo
	if !filepath.IsAbs(selected) {
		return zero, errors.New("выберите файл приложения")
	}
	name := ""
	if runtime.GOOS == "darwin" && strings.EqualFold(filepath.Ext(selected), ".app") {
		bundle, err := filepath.EvalSymlinks(selected)
		if err != nil {
			return zero, err
		}
		raw, err := exec.CommandContext(ctx, "/usr/bin/plutil", "-extract", "CFBundleExecutable", "raw", "-o", "-", "--", filepath.Join(bundle, "Contents", "Info.plist")).Output()
		exe := strings.TrimSuffix(string(raw), "\n")
		if err != nil || exe == "" || exe == "." || exe == ".." || filepath.Base(exe) != exe || len(exe) > 255 {
			return zero, errors.New("в пакете .app не найден исполняемый файл")
		}
		selected, err = filepath.EvalSymlinks(filepath.Join(bundle, "Contents", "MacOS", exe))
		if err != nil || !strings.HasPrefix(selected, bundle+string(os.PathSeparator)) {
			return zero, errors.New("исполняемый файл должен находиться внутри выбранного .app")
		}
		name = strings.TrimSuffix(filepath.Base(bundle), filepath.Ext(bundle))
	}
	path, stat, err := executableFile(selected)
	if err != nil {
		return zero, err
	}
	if runtime.GOOS == "windows" {
		if !strings.EqualFold(filepath.Ext(path), ".exe") {
			return zero, errors.New("выберите исполняемый файл .exe")
		}
		binary, err := pe.Open(path)
		if err != nil {
			return zero, errors.New("выбранный файл не является программой Windows")
		}
		binary.Close()
		if binary.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 || binary.Characteristics&pe.IMAGE_FILE_DLL != 0 {
			return zero, errors.New("выберите исполняемую программу Windows")
		}
	} else if stat.Mode().Perm()&0111 == 0 {
		return zero, errors.New("у выбранного файла нет права на выполнение")
	} else if runtime.GOOS == "darwin" {
		// Scripts run under their interpreter's process identity.
		f, err := os.Open(path)
		if err != nil {
			return zero, err
		}
		var magic [4]byte
		_, err = io.ReadFull(f, magic[:])
		f.Close()
		if err != nil || !machExecutable(binary.BigEndian.Uint32(magic[:])) && !machExecutable(binary.LittleEndian.Uint32(magic[:])) {
			return zero, errors.New("выберите приложение .app или исполняемый файл macOS")
		}
	}
	return executableIdentity(path, name, stat)
}

func machExecutable(magic uint32) bool {
	// FAT_MAGIC_64 is the wide-offset variant of macho.MagicFat.
	return magic == macho.Magic32 || magic == macho.Magic64 || magic == macho.MagicFat || magic == 0xcafebabf
}
