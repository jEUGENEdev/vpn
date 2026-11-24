package secure

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func checkDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secret directory must not be a link")
	}
	return nil
}

func protectFile(f *os.File) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	// Protected DACL replaces inherited Users/Everyone access before secret bytes
	// are written. Service state remains readable by SYSTEM and Administrators.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(f.Name(), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// Windows does not support directory fsync via os.File.Sync. The temp file is
// flushed before replacement; power-loss durability of the directory is not a
// guarantee of this backend.
func syncDirectory(string) error { return nil }
