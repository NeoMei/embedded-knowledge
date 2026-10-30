//go:build windows

package service

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A key is opened relative to a pinned private directory, never by reopening
// its path after checking permissions. The local privileged Windows principals
// remain trusted, as root does on Unix. Unknown ACL forms fail closed.
func readManagedKeyFile(path string) ([]byte, error) {
	if !managedWindowsKeyPath(path) {
		return nil, ErrManagedWorkerUnavailable
	}
	if windows.GetDriveType(windows.StringToUTF16Ptr(path[:3])) != windows.DRIVE_FIXED {
		return nil, ErrManagedWorkerUnavailable
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, ErrManagedWorkerUnavailable
	}
	directory, name := filepath.Split(path)
	parent, err := managedWindowsOpen(0, `\??\`+filepath.Clean(directory), true)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	defer windows.CloseHandle(parent)
	parentBefore, parentACL, err := managedWindowsCheck(parent, user.User.Sid, true)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	handle, err := managedWindowsOpen(parent, name, false)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrManagedWorkerUnavailable
	}
	defer file.Close()
	before, aclBefore, err := managedWindowsCheck(handle, user.User.Sid, false)
	if err != nil {
		return nil, ErrManagedWorkerUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(data) != 32 {
		return nil, ErrManagedWorkerUnavailable
	}
	after, aclAfter, err := managedWindowsCheck(handle, user.User.Sid, false)
	if err != nil || before != after || aclBefore != aclAfter {
		return nil, ErrManagedWorkerUnavailable
	}
	parentAfter, parentACLAfter, err := managedWindowsCheck(parent, user.User.Sid, true)
	if err != nil || parentBefore != parentAfter || parentACL != parentACLAfter {
		return nil, ErrManagedWorkerUnavailable
	}
	return data, nil
}

func managedWindowsKeyPath(path string) bool {
	// Accept only unambiguous local drive paths. In particular, Win32's implicit
	// trailing-dot/space, device-name and alternate-stream aliases are excluded.
	if len(path) < 4 || path[1] != ':' || path[2] != '\\' ||
		!((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "/\x00") {
		return false
	}
	for _, component := range strings.Split(path[3:], `\`) {
		if component == "" || strings.TrimRight(component, " .") != component || strings.ContainsAny(component, ":*?\"<>|") {
			return false
		}
		stem := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
			managedWindowsDeviceName(stem) {
			return false
		}
	}
	return true
}

func managedWindowsDeviceName(name string) bool {
	for _, prefix := range []string{"COM", "LPT"} {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		suffix := []rune(strings.TrimPrefix(name, prefix))
		if len(suffix) == 1 && strings.ContainsRune("123456789¹²³", suffix[0]) {
			return true
		}
	}
	return false
}

func managedWindowsOpen(parent windows.Handle, name string, directory bool) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
		access |= windows.FILE_TRAVERSE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
		access |= windows.FILE_READ_DATA
	}
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, access, &attributes, &windows.IO_STATUS_BLOCK{}, nil, 0,
		windows.FILE_SHARE_READ, windows.FILE_OPEN, options, 0, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return handle, nil
}

func managedWindowsCheck(handle windows.Handle, user *windows.SID, directory bool) (windows.ByHandleFileInformation, string, error) {
	var info windows.ByHandleFileInformation
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(handle, &info) != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory ||
		(!directory && (info.FileSizeHigh != 0 || info.FileSizeLow != 32 || info.NumberOfLinks != 1)) {
		return info, "", ErrManagedWorkerUnavailable
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil || !sd.IsValid() || !managedWindowsPrivateACL(sd, user) {
		return info, "", ErrManagedWorkerUnavailable
	}
	acl := sd.String()
	if acl == "" {
		return info, "", ErrManagedWorkerUnavailable
	}
	// Read access-time updates are incidental; identity, size, attributes,
	// write-time, links and ACL must remain stable on the very same handles.
	info.LastAccessTime = windows.Filetime{}
	return info, acl, nil
}

func managedWindowsPrivateACL(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) bool {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		return false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return false
	}
	defer runtime.KeepAlive(sd)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace == nil ||
			uintptr(ace.Header.AceSize) < unsafe.Offsetof(ace.SidStart)+8 {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.IsValid() || uintptr(sid.Len()) > uintptr(ace.Header.AceSize)-unsafe.Offsetof(ace.SidStart) ||
				!(sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
