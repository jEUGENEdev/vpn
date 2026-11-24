package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/jEUGENEdev/vpn/internal/platform"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// MSI executes this copy from its Binary table, so removal still works when
// the installed agent is missing. No path comes from MSI properties or -data.
func cleanInstallation(fresh bool) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("для установки и удаления требуются права администратора")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	service, err := m.OpenService("LineVPN")
	if err == nil {
		defer service.Close()
		status, e := service.Query()
		if e != nil {
			return e
		}
		if fresh || status.State != svc.Stopped {
			return errors.New("сначала удалите прежнюю установку «Сеть»; служба должна быть остановлена")
		}
	} else if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	if err = closeInstalledUI(); err != nil {
		return err
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return err
	}
	dir := filepath.Join(base, "LineVPN")
	// An old MSI may have left the entire data directory on explicit removal.
	// The fresh package must never load those credentials or disabled intent.
	if err = platform.Recover(dir); err != nil {
		return err
	}
	if err = removeOwnedDirectory(dir); err != nil {
		return err
	}
	profiles, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.READ)
	if err != nil {
		return err
	}
	defer profiles.Close()
	names, err := profiles.ReadSubKeyNames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		profile, e := registry.OpenKey(profiles, name, registry.READ)
		if e != nil {
			return e
		}
		home, _, e := profile.GetStringValue("ProfileImagePath")
		profile.Close()
		if e != nil {
			return e
		}
		home, e = registry.ExpandString(home)
		if e != nil {
			return e
		}
		if !filepath.IsAbs(home) {
			return errors.New("invalid Windows profile path")
		}
		if e = removeOwnedDirectory(filepath.Join(home, "AppData", "Roaming", "LineVPN")); e != nil {
			return e
		}
	}
	if fresh {
		base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if err != nil {
			return err
		}
		// The previous MSI has already been removed and no worker is alive.
		// Clear stale payload too, so Windows file-version rules cannot retain it.
		return removeOwnedDirectory(filepath.Join(base, "LineVPN"))
	}
	return nil
}

func closeInstalledUI() error {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return err
	}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	err = windows.Process32First(snapshot, &entry)
	for err == nil {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, "Сеть.exe") || strings.EqualFold(name, "LineVPN.exe") || strings.EqualFold(name, "linevpn-agent.exe") {
			process, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, entry.ProcessID)
			if e != nil {
				if !errors.Is(e, windows.ERROR_INVALID_PARAMETER) {
					return e
				}
			} else {
				buffer := make([]uint16, 32768)
				size := uint32(len(buffer))
				e = windows.QueryFullProcessImageName(process, 0, &buffer[0], &size)
				installed := filepath.Join(base, "LineVPN", name)
				if strings.EqualFold(name, "linevpn-agent.exe") {
					installed = filepath.Join(base, "LineVPN", "resources", "agent", name)
				}
				if e == nil && strings.EqualFold(windows.UTF16ToString(buffer[:size]), installed) {
					if strings.EqualFold(name, "linevpn-agent.exe") {
						windows.CloseHandle(process)
						return errors.New("прежний процесс службы ещё работает; завершите удаление или перезагрузите Windows")
					}
					e = windows.TerminateProcess(process, 0)
					if e == nil {
						var result uint32
						result, e = windows.WaitForSingleObject(process, 10000)
						if e == nil && result != windows.WAIT_OBJECT_0 {
							e = errors.New("приложение «Сеть» не завершилось")
						}
					}
				}
				windows.CloseHandle(process)
				if e != nil {
					return fmt.Errorf("stop installed UI: %w", e)
				}
			}
		}
		err = windows.Process32Next(snapshot, &entry)
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil
	}
	return err
}
