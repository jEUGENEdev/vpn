package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func openDesktopOperator(dir string) (*desktopOperator, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\LineVPN\Installer`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer key.Close()
	value, _, err := key.GetStringValue("DesktopOperatorSID")
	if errors.Is(err, registry.ErrNotExist) || (err == nil && value == "") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sid, err := windows.StringToSid(value)
	if err != nil {
		return nil, err
	}
	_, _, kind, err := sid.LookupAccount("")
	if err != nil {
		return nil, err
	}
	if kind != windows.SidTypeUser {
		return nil, nil // Unattended installs may belong to LocalSystem.
	}
	path := filepath.Join(dir, "desktop-operator.json")
	token, err := writeOperatorToken(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;" + sid.String() + ")")
	if err != nil {
		return nil, err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return nil, err
	}
	return &desktopOperator{token: token, confirm: func(ctx context.Context, summary string) (bool, error) {
		return promptWindowsOperator(ctx, sid, summary)
	}}, nil
}

func operatorSession(sid *windows.SID) (uint32, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	var id uint32
	for _, s := range unsafe.Slice(sessions, count) {
		if s.State != windows.WTSActive || s.SessionID == 0 {
			continue
		}
		var token windows.Token
		if windows.WTSQueryUserToken(s.SessionID, &token) != nil {
			continue
		}
		user, err := token.GetTokenUser()
		token.Close()
		if err == nil && user.User.Sid.Equals(sid) {
			if id != 0 {
				return 0, errors.New("несколько активных сеансов пользователя")
			}
			id = s.SessionID
		}
	}
	if id == 0 {
		return 0, errors.New("нет активного сеанса пользователя")
	}
	return id, nil
}

var sendOperatorMessage = windows.NewLazySystemDLL("wtsapi32.dll").NewProc("WTSSendMessageW")

func promptWindowsOperator(ctx context.Context, sid *windows.SID, summary string) (bool, error) {
	id, err := operatorSession(sid)
	if err != nil {
		return false, err
	}
	title, _ := windows.UTF16FromString("Сеть — подтверждение")
	message, err := windows.UTF16FromString(summary)
	if err != nil {
		return false, err
	}
	deadline, _ := ctx.Deadline()
	seconds := int(time.Until(deadline).Seconds())
	if seconds < 1 {
		return false, context.DeadlineExceeded
	}
	var response uint32
	// MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2. Default and timeout deny.
	ok, _, callErr := sendOperatorMessage.Call(0, uintptr(id), uintptr(unsafe.Pointer(&title[0])), uintptr((len(title)-1)*2),
		uintptr(unsafe.Pointer(&message[0])), uintptr((len(message)-1)*2), 0x134, uintptr(seconds), uintptr(unsafe.Pointer(&response)), 1)
	if ok == 0 {
		return false, callErr
	}
	current, err := operatorSession(sid)
	return response == 6 && current == id && ctx.Err() == nil, err
}

func serveOperatorDialog(string) error { return errors.New("desktop dialog helper is macOS only") }
