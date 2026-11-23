package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"path/filepath"
	"unsafe"
)

func privilegedControlPath() (string, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return "", errors.New("для изменения настроек требуется UAC")
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "LineVPN", "control", "session.json"), nil
}
func confirmControl(description string) bool {
	message, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return false
	}
	title, _ := windows.UTF16PtrFromString("Сеть — изменение настроек")
	// Yes/No, warning, default No. The elevated dialog is protected by UIPI.
	result, _, _ := windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x4|0x30|0x100|0x10000)
	return result == 6
}
