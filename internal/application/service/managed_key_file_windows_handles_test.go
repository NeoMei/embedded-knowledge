//go:build windows

package service

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestManagedWindowsKeyFileRejectsJunction(t *testing.T) {
	dir, _, _ := managedWindowsTestKey(t)
	junction := filepath.Join(t.TempDir(), "junction")
	if err := os.Mkdir(junction, 0700); err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(windows.StringToUTF16Ptr(junction), windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	substitute, err := windows.UTF16FromString(`\??\` + dir)
	if err != nil {
		windows.CloseHandle(handle)
		t.Fatal(err)
	}
	printName, err := windows.UTF16FromString(dir)
	if err != nil {
		windows.CloseHandle(handle)
		t.Fatal(err)
	}
	data := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(data, windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(data[4:], uint16(len(data)-8))
	binary.LittleEndian.PutUint16(data[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(data[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(data[14:], uint16(2*(len(printName)-1)))
	for i, value := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(data[16+2*i:], value)
	}
	var returned uint32
	err = windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &data[0], uint32(len(data)), nil, 0, &returned, nil)
	windows.CloseHandle(handle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedKeyFile(filepath.Join(junction, "managed.key")); err == nil {
		t.Fatal("junction followed")
	}
}

func TestManagedWindowsKeyFilePinsParentAndKey(t *testing.T) {
	dir, file, _ := managedWindowsTestKey(t)
	parent, err := managedWindowsOpen(0, `\??\`+dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(parent)
	child, err := managedWindowsOpen(parent, filepath.Base(file), false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(child)
	if _, _, err := managedWindowsCheck(parent, managedWindowsTestUser(t), true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := managedWindowsCheck(child, managedWindowsTestUser(t), false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, file} {
		if err := os.Rename(path, path+"-replaced"); err == nil {
			t.Fatalf("pinned parent/key can be renamed: %s", filepath.Base(path))
		}
	}
	writer, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err == nil {
		writer.Close()
		t.Fatal("key can be modified while verified reader holds handle")
	}
}

func TestManagedWindowsKeyFileRejectsExistingWriter(t *testing.T) {
	_, file, _ := managedWindowsTestKey(t)
	writer, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := readManagedKeyFile(file); err == nil {
		t.Fatal("concurrently writable key accepted")
	}
}

func TestManagedWindowsKeyFileRejectsPermissionDrift(t *testing.T) {
	_, file, _ := managedWindowsTestKey(t)
	reader, err := managedWindowsOpen(0, `\??\`+file, false)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(reader)
	if _, _, err := managedWindowsCheck(reader, managedWindowsTestUser(t), false); err != nil {
		t.Fatal(err)
	}
	managedWindowsTestACL(t, file, "(A;;FR;;;WD)")
	if _, _, err := managedWindowsCheck(reader, managedWindowsTestUser(t), false); err == nil {
		t.Fatal("same-handle ACL recheck accepted permissive drift")
	}
}

func TestManagedWindowsKeyFileRejectsNullACLAndWrongOwner(t *testing.T) {
	user := managedWindowsTestUser(t)
	for _, sddl := range []string{
		"O:" + user.String(),
		"O:" + user.String() + "D:NO_ACCESS_CONTROL",
		"O:SYD:P(A;;FA;;;" + user.String() + ")",
		"O:" + user.String() + "D:P(A;;FR;;;WD)(D;;FR;;;WD)(A;;FA;;;" + user.String() + ")",
		"O:" + user.String() + "D:P(A;IO;FR;;;WD)(A;;FA;;;" + user.String() + ")",
	} {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if managedWindowsPrivateACL(sd, user) {
			t.Fatal("missing/null/non-private ACL or non-user owner accepted")
		}
	}
}

func TestManagedWindowsActualUserConfigHostLayout(t *testing.T) {
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(config, "managed-key-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	keys := filepath.Join(directory, "managed-knowledge", "keys")
	if err := os.MkdirAll(keys, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(keys, "callback.key")
	if err := os.WriteFile(file, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	// Do not repair the OS default owner or inherited ACL. A failure here is a
	// concrete host-integration gap, including an elevated process that creates
	// Administrators-owned files, rather than permission to relax the reader.
	if _, err := readManagedKeyFile(file); err != nil {
		for _, path := range []string{keys, file} {
			sd, aclErr := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if aclErr == nil {
				t.Logf("default %s security descriptor: %s", filepath.Base(path), sd.String())
			}
		}
		t.Fatalf("actual UserConfigDir host layout is not private/current-user-owned: %v", err)
	}
}
