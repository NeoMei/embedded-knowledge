//go:build windows

package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func managedWindowsTestUser(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid
}

func managedWindowsTestACL(t *testing.T, path, additional string) {
	t.Helper()
	user := managedWindowsTestUser(t).String()
	inherit := ""
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		inherit = "OICI"
	}
	sddl := "O:" + user + "D:P(A;" + inherit + ";FA;;;" + user + ")(A;" + inherit + ";FA;;;SY)(A;" + inherit + ";FA;;;BA)" + additional
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func managedWindowsTestKey(t *testing.T) (string, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	managedWindowsTestACL(t, dir, "")
	key := bytes.Repeat([]byte{0x42}, 32)
	file := filepath.Join(dir, "managed.key")
	if err := os.WriteFile(file, key, 0600); err != nil {
		t.Fatal(err)
	}
	managedWindowsTestACL(t, file, "")
	return dir, file, key
}

func TestManagedWindowsKeyFileReadsPrivateOwnerKey(t *testing.T) {
	_, file, key := managedWindowsTestKey(t)
	got, err := readManagedKeyFile(file)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("private current-user/SYSTEM/Administrators key rejected: %v", err)
	}
}

func TestManagedWindowsKeyFileRejectsUnsafeFiles(t *testing.T) {
	for _, target := range []string{"file", "parent"} {
		for _, grant := range []string{"(A;;FR;;;WD)", "(A;;FW;;;AU)", "(A;;WD;;;BU)", "(A;;SD;;;WD)"} {
			t.Run(target+grant, func(t *testing.T) {
				dir, file, _ := managedWindowsTestKey(t)
				path := file
				if target == "parent" {
					path = dir
				}
				managedWindowsTestACL(t, path, grant)
				if _, err := readManagedKeyFile(file); err == nil {
					t.Fatal("non-private ACL accepted")
				}
			})
		}
	}
	for _, size := range []int{0, 31, 33, 65536} {
		t.Run(fmt.Sprint("size-", size), func(t *testing.T) {
			_, file, _ := managedWindowsTestKey(t)
			if err := os.WriteFile(file, bytes.Repeat([]byte{'x'}, size), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readManagedKeyFile(file); err == nil {
				t.Fatal("wrong key length accepted")
			}
		})
	}
	t.Run("directory", func(t *testing.T) {
		dir, _, _ := managedWindowsTestKey(t)
		if _, err := readManagedKeyFile(dir); err == nil {
			t.Fatal("directory accepted")
		}
	})
	t.Run("alternate-stream", func(t *testing.T) {
		_, file, _ := managedWindowsTestKey(t)
		if _, err := readManagedKeyFile(file + ":hidden"); err == nil {
			t.Fatal("alternate data stream accepted")
		}
	})
	t.Run("hard-link", func(t *testing.T) {
		dir, file, _ := managedWindowsTestKey(t)
		if err := os.Link(file, filepath.Join(dir, "other.key")); err != nil {
			t.Fatal(err)
		}
		if _, err := readManagedKeyFile(file); err == nil {
			t.Fatal("multiply linked key accepted")
		}
	})
}

func TestManagedWindowsKeyFileRejectsAmbiguousPaths(t *testing.T) {
	for _, path := range []string{
		"managed.key", `C:managed.key`, `\managed.key`, `\\server\share\managed.key`,
		`\\?\C:\private\managed.key`, `\\.\pipe\managed.key`, `C:\private\..\managed.key`,
		`C:/private/managed.key`, `C:\private\.\managed.key`, `C:\private\managed.key.`,
		`C:\private\managed.key `, `C:\private\managed.key:stream`, `C:\private\NUL`,
		`C:\private\con.txt`, `C:\private\LPT1`, "C:\\private\\managed\x00.key",
		`C:\private\COM¹.key`, `C:\private\LPT²`,
	} {
		t.Run(strings.ReplaceAll(path, "\\", "_"), func(t *testing.T) {
			if _, err := readManagedKeyFile(path); err == nil {
				t.Fatal("ambiguous or non-local path accepted")
			}
		})
	}
}

func TestManagedWindowsKeyFileRejectsReparsePoints(t *testing.T) {
	dir, file, _ := managedWindowsTestKey(t)
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(file, link); err != nil {
		t.Fatalf("native Windows acceptance must permit test symlinks: %v", err)
	}
	if _, err := readManagedKeyFile(link); err == nil {
		t.Fatal("leaf reparse point followed")
	}
	parent := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(dir, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedKeyFile(filepath.Join(parent, "managed.key")); err == nil {
		t.Fatal("parent reparse point followed")
	}
	ancestor := filepath.Join(t.TempDir(), "ancestor-link")
	if err := os.Symlink(filepath.Dir(dir), ancestor); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedKeyFile(filepath.Join(ancestor, filepath.Base(dir), "managed.key")); err == nil {
		t.Fatal("ancestor reparse point followed")
	}
}

func TestManagedWindowsHostLayoutInheritedPermissions(t *testing.T) {
	// Mirrors mkdir(0700), nested mkdir, and writeFile(0600) on Windows. The
	// user-private AppData boundary is represented by an actual private ACL;
	// child permissions are left to the OS, not manually repaired.
	appData := t.TempDir()
	managedWindowsTestACL(t, appData, "")
	dir := filepath.Join(appData, "SuperWagie", "managed-knowledge", "keys")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "callback.key")
	key := bytes.Repeat([]byte{'h'}, 32)
	if err := os.WriteFile(file, key, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readManagedKeyFile(file)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("OS-inherited private host layout rejected: %v", err)
	}
}
