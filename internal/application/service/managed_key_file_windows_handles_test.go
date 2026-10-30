//go:build windows

package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

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
	prepared := filepath.Join(directory, "production-private", "callback.key")
	managedWindowsVerifyRawAndPreparedHostLayout(t, file, prepared, make([]byte, 32))
}

func TestManagedWindowsProductionHostKeepsUnsafeExistingKeys(t *testing.T) {
	dir, file, key := managedWindowsTestKey(t)
	managedWindowsTestACL(t, file, "(A;;FR;;;WD)")
	before, err := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if managedWindowsHostCommand(t, file, "create") == nil {
		t.Fatal("production host accepted an exposed existing key")
	}
	after, err := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || before.String() != after.String() {
		t.Fatal("production host changed exposed existing ACL")
	}
	if got, err := os.ReadFile(file); err != nil || !bytes.Equal(got, key) {
		t.Fatal("production host overwrote exposed existing bytes")
	}
	link := filepath.Join(t.TempDir(), "linked-directory")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if managedWindowsHostCommand(t, filepath.Join(link, "new.key"), "create") == nil {
		t.Fatal("production host followed a reparse directory")
	}
}

func TestManagedWindowsProductionHostPreparesEveryKeyKind(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{"key-v1", "journal-v1.key", "call-v1.key", "binding-v1.key", "callback-v1.key", "literal'$(ignored);.key", "专用密钥.key"} {
		file := filepath.Join(parent, "production-private", name)
		if err := managedWindowsHostCommand(t, file, "create"); err != nil {
			t.Fatalf("production host failed key kind %s: %v", name, err)
		}
		if got, err := readManagedKeyFile(file); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{'h'}, 32)) {
			t.Fatalf("strict worker failed key kind %s: %v", name, err)
		}
	}
	callback := filepath.Join(parent, "ephemeral-private", "key")
	if err := managedWindowsHostCommand(t, callback, "create"); err != nil {
		t.Fatal(err)
	}
	if _, err := readManagedKeyFile(callback); err != nil {
		t.Fatal(err)
	}
}

// Only an exclusively created target belongs to this invocation. Existing
// private directories keep their exact owner/DACL, including on repeat calls.
func TestManagedWindowsProductionHostDirectoryOwnership(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "exclusive-private")
	if err := managedWindowsHostCommand(t, directory, "directory-concurrent"); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !managedWindowsPrivateACL(before, managedWindowsTestUser(t)) {
		t.Fatal("new host directory is not user-owned and private")
	}
	if err := managedWindowsHostCommand(t, directory, "directory-existing"); err != nil {
		t.Fatal("existing directory reported as new", err)
	}
	after, err := windows.GetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || before.String() != after.String() {
		t.Fatal("existing directory descriptor changed")
	}
}

func TestManagedWindowsProductionHostHoldsVerifiedEmptyFile(t *testing.T) {
	helper := os.Getenv("WEKNORA_TEST_MANAGED_HOST_MODULE")
	if helper == "" {
		helper = filepath.Join("..", "..", "..", "scripts", "fixtures", "managed-key-storage.mjs")
	}
	helper, err := filepath.Abs(helper)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "held-private", "callback.key")
	const script = `const {pathToFileURL}=require('node:url'); const path=require('node:path');
import(pathToFileURL(process.argv[1]).href).then(async({createManagedKeyStorage})=>{
 const storage=createManagedKeyStorage(); const filename=process.argv[2];
 await storage.prepareDirectory(path.dirname(filename)); const file=await storage.createFile(filename);
 console.log('private_empty_ready');
 process.stdin.once('data',async()=>{try{await file.writeFile(Buffer.alloc(32,104));await file.sync();}catch{process.exitCode=1;}finally{await file.close();}});
}).catch(()=>{console.error('production_host_key_refused');process.exitCode=1;});`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", "-e", script, helper, file)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	lines := bufio.NewScanner(output)
	if !lines.Scan() || lines.Text() != "private_empty_ready" {
		t.Fatalf("host did not hold an empty private file: %s", diagnostics.String())
	}
	descriptor, err := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !managedWindowsPrivateACL(descriptor, managedWindowsTestUser(t)) {
		t.Fatal("pre-write file owner/DACL invalid", err)
	}
	if info, err := os.Stat(file); err != nil || info.Size() != 0 {
		t.Fatal("key bytes written before caller supplied them")
	}
	writer, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err == nil {
		writer.Close()
		t.Fatal("native private creator released its file before writing")
	}
	if err := os.Rename(filepath.Dir(file), filepath.Dir(file)+"-replaced"); err == nil {
		t.Fatal("native private creator released the parent before writing")
	}
	if _, err := input.Write([]byte("continue")); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("host write failed: %v %s", err, diagnostics.String())
	}
	if got, err := readManagedKeyFile(file); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{'h'}, 32)) {
		t.Fatal("strict reader rejected same-handle host write", err)
	}
}
