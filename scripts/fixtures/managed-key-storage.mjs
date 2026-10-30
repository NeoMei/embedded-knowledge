import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';

// The Windows helper pins every ancestor and creates with an explicit owner/DACL.
// It validates and writes the key on one native file handle. Only the private
// stdin pipe carries the 32 key bytes, after the helper acknowledges readiness.
const windowsNativeStorage = String.raw`
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class ManagedPrivateStorage {
  const uint ReadControl = 0x20000, Synchronize = 0x100000, ReadAttributes = 0x80;
  const uint DirectoryOptions = 0x00200021, FileOptions = 0x00200060;
  const uint AncestorReadOrCreateRights = 0xa01200af;
  const int Missing = unchecked((int)0xc0000034), MissingPath = unchecked((int)0xc000003a), Exists = unchecked((int)0xc0000035);
  static readonly string User = WindowsIdentity.GetCurrent().User.Value;
  static readonly string SystemUser = "S-1-5-18", Admins = "S-1-5-32-544";
  static readonly string Installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
  [StructLayout(LayoutKind.Sequential)] struct UnicodeName { public ushort Length, MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct ObjectAttributes { public uint Length; public IntPtr Root, Name; public uint Flags; public IntPtr Security, SecurityQoS; }
  [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr Status, Information; }
  [StructLayout(LayoutKind.Sequential)] struct FileInformation {
    public uint Attributes, CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
    public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("ntdll.dll")] static extern int NtCreateFile(out SafeFileHandle handle, uint access, ref ObjectAttributes attributes, out IoStatus status, IntPtr allocation, uint fileAttributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
  [DllImport("kernel32.dll")] static extern uint GetFileType(SafeFileHandle handle);
  [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr security);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr security);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);

  static SafeFileHandle Open(SafeFileHandle parent, string name, bool directory, bool create, out int status) {
    IntPtr text = Marshal.StringToHGlobalUni(name), unicode = IntPtr.Zero, security = IntPtr.Zero;
    try {
      UnicodeName value = new UnicodeName { Length = checked((ushort)(name.Length * 2)), MaximumLength = checked((ushort)(name.Length * 2 + 2)), Buffer = text };
      unicode = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeName))); Marshal.StructureToPtr(value, unicode, false);
      if (create) {
        string inheritance = directory ? "OICI" : "";
        RawSecurityDescriptor descriptor = new RawSecurityDescriptor("O:" + User + "D:P(A;" + inheritance + ";FA;;;" + User + ")(A;" + inheritance + ";FA;;;SY)(A;" + inheritance + ";FA;;;BA)");
        byte[] bytes = new byte[descriptor.BinaryLength]; descriptor.GetBinaryForm(bytes, 0);
        security = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, security, bytes.Length);
      }
      ObjectAttributes attributes = new ObjectAttributes { Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)), Root = parent == null ? IntPtr.Zero : parent.DangerousGetHandle(), Name = unicode, Flags = 0x1040, Security = security };
      uint access = ReadControl | Synchronize | ReadAttributes | (directory ? 0x20u : create ? 3u : 1u);
      IoStatus io; SafeFileHandle handle;
      status = NtCreateFile(out handle, access, ref attributes, out io, IntPtr.Zero, directory ? 0u : 0x80u, directory ? 3u : create ? 0u : 1u, create ? 2u : 1u, directory ? DirectoryOptions : FileOptions, IntPtr.Zero, 0);
      if (status != 0 || (create && io.Information.ToInt64() != 2)) { if (handle != null) handle.Dispose(); return null; }
      return handle;
    } finally {
      if (security != IntPtr.Zero) Marshal.FreeHGlobal(security);
      if (unicode != IntPtr.Zero) Marshal.FreeHGlobal(unicode);
      Marshal.FreeHGlobal(text);
    }
  }

  static bool Privileged(string sid) { return sid == User || sid == SystemUser || sid == Admins; }
  static string Check(SafeFileHandle handle, bool directory, bool privateTarget, uint size) {
    FileInformation info;
    if (GetFileType(handle) != 1 || !GetFileInformationByHandle(handle, out info) || (info.Attributes & 0x400) != 0 || ((info.Attributes & 0x10) != 0) != directory ||
        (!directory && (info.SizeHigh != 0 || info.SizeLow != size || info.Links != 1))) throw new IOException("kind");
    IntPtr owner, group, dacl, sacl, security;
    uint error = GetSecurityInfo(handle, 1, 5, out owner, out group, out dacl, out sacl, out security);
    if (error != 0 || security == IntPtr.Zero) throw new IOException("security");
    try {
      byte[] bytes = new byte[checked((int)GetSecurityDescriptorLength(security))]; Marshal.Copy(security, bytes, 0, bytes.Length);
      RawSecurityDescriptor descriptor = new RawSecurityDescriptor(bytes, 0);
      if (descriptor.Owner == null || (privateTarget ? descriptor.Owner.Value != User : !Privileged(descriptor.Owner.Value) && descriptor.Owner.Value != Installer) ||
          (descriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0 || descriptor.DiscretionaryAcl == null || descriptor.DiscretionaryAcl.Count == 0) throw new IOException("owner or acl");
      foreach (GenericAce item in descriptor.DiscretionaryAcl) {
        CommonAce ace = item as CommonAce;
        if (ace == null || ace.IsCallback) throw new IOException("acl kind");
        if (ace.AceQualifier == AceQualifier.AccessDenied) continue;
        if (ace.AceQualifier != AceQualifier.AccessAllowed) throw new IOException("acl grant");
        if (Privileged(ace.SecurityIdentifier.Value) || (!privateTarget && ace.SecurityIdentifier.Value == Installer)) continue;
        if (privateTarget) throw new IOException("private grant");
        // Structural ancestors may allow listing/traversal and creating a
        // different child. They must prevent untrusted principals changing or
        // deleting this existing directory, its ACL, or an existing child.
        if ((ace.AceFlags & AceFlags.InheritOnly) == 0 && (unchecked((uint)ace.AccessMask) & ~AncestorReadOrCreateRights) != 0) throw new IOException("ancestor grant");
      }
      return Convert.ToBase64String(bytes);
    } finally { LocalFree(security); }
  }

  public static void Run(string operation, string path, Stream input) {
    Console.Out.NewLine = "\n";
    List<SafeFileHandle> ancestors = new List<SafeFileHandle>(); List<string> permissions = new List<string>();
    SafeFileHandle file = null;
    try {
      int status; SafeFileHandle current = Open(null, @"\??\" + path.Substring(0, 3), true, false, out status);
      if (current == null) throw new IOException("root"); ancestors.Add(current); permissions.Add(Check(current, true, false, 0));
      string[] parts = path.Substring(3).Split('\\'); bool createdDirectory = false;
      int count = operation == "directory" ? parts.Length : parts.Length - 1;
      for (int index = 0; index < count; index++) {
        SafeFileHandle next = Open(current, parts[index], true, false, out status); bool created = false;
        if (next == null && (status == Missing || status == MissingPath) && operation == "directory") {
          next = Open(current, parts[index], true, true, out status); created = next != null;
          // A concurrent creator owns that object. Only inspect it; never
          // change its descriptor or report it as our creation.
          if (next == null && status == Exists) next = Open(current, parts[index], true, false, out status);
        }
        if (next == null) throw new IOException("directory");
        ancestors.Add(next); permissions.Add(Check(next, true, created || index == count - 1, 0)); current = next;
        if (index == count - 1) createdDirectory = created;
      }
      if (operation == "directory") { Console.Out.WriteLine(createdDirectory ? "{\"created\":true}" : "{\"created\":false}"); return; }
      if (operation == "create-file") {
        file = Open(current, parts[parts.Length - 1], false, true, out status);
        if (file != null) {
          string initial = Check(file, false, true, 0);
          for (int index = 0; index < ancestors.Count; index++) {
            if (Check(ancestors[index], true, index == ancestors.Count - 1, 0) != permissions[index]) throw new IOException("changed parent");
          }
          Console.Out.WriteLine("{\"created\":true}"); Console.Out.Flush();
          byte[] key = new byte[32];
          try {
            int length = 0, read; while (length < key.Length && (read = input.Read(key, length, key.Length - length)) > 0) length += read;
            if (length != key.Length || input.ReadByte() != -1) throw new IOException("key length");
            // The descriptor and empty size are checked on this exact native
            // file handle again immediately before the first secret write.
            if (Check(file, false, true, 0) != initial) throw new IOException("changed file");
            for (int index = 0; index < ancestors.Count; index++) {
              if (Check(ancestors[index], true, index == ancestors.Count - 1, 0) != permissions[index]) throw new IOException("changed parent");
            }
            using (FileStream stream = new FileStream(file, FileAccess.ReadWrite, 4096, false)) {
              stream.Write(key, 0, key.Length); stream.Flush(true); Check(stream.SafeFileHandle, false, true, 32);
            }
            file = null;
          } finally { Array.Clear(key, 0, key.Length); }
          Console.Out.WriteLine("{\"written\":true}"); return;
        }
        if (status != Exists) throw new IOException("create file");
      }
      file = Open(current, parts[parts.Length - 1], false, false, out status);
      if (file == null) throw new IOException("existing file"); Check(file, false, true, 32);
      Console.Out.WriteLine("{\"created\":false}");
    } finally {
      if (file != null) file.Dispose();
      for (int index = ancestors.Count - 1; index >= 0; index--) ancestors[index].Dispose();
    }
  }
}
`;

const windowsPreparation = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
  $stdin = [Console]::OpenStandardInput()
  function ReadBoundedLine([int]$limit) {
    $bytes = [Collections.Generic.List[byte]]::new()
    while (($value = $stdin.ReadByte()) -ne 10) {
      if ($value -lt 0 -or $bytes.Count -ge $limit) { throw 'input' }
      $bytes.Add([byte]$value)
    }
    return [Text.UTF8Encoding]::new($false, $true).GetString($bytes.ToArray())
  }
  $sourceLine = ReadBoundedLine 40000
  $source = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($sourceLine))
  $metadataLine = ReadBoundedLine 32768
  Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')) -ErrorAction Stop
  $inputValue = ConvertFrom-Json -InputObject $metadataLine
  if (@($inputValue.PSObject.Properties.Name).Count -ne 2 -or
      $inputValue.operation -notin @('directory', 'create-file', 'verify-file')) { throw 'invalid' }
  $target = [string]$inputValue.path
  if ($target.Length -gt 8000 -or $target -notmatch '^[A-Za-z]:\\' -or $target.Contains('/') -or
      [IO.Path]::GetFullPath($target) -cne $target -or $target.Substring(2).Contains(':')) { throw 'invalid' }
  foreach ($part in $target.Substring(3).Split('\')) {
    if (!$part -or $part.TrimEnd(' ', '.') -cne $part -or $part.IndexOfAny([char[]]'*?"<>|') -ge 0 -or
        $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)') { throw 'invalid' }
  }
  if (([IO.DriveInfo]::new($target.Substring(0, 3))).DriveType -ne [IO.DriveType]::Fixed) { throw 'invalid' }
  Add-Type -TypeDefinition $source -ErrorAction Stop | Out-Null
  [ManagedPrivateStorage]::Run([string]$inputValue.operation, $target, $stdin)
} catch {
  [Console]::Error.WriteLine('managed_key_storage_unavailable')
  exit 1
}
`;

const unavailable = () => Object.assign(new Error('knowledge_work_storage_unavailable'), { code: 'knowledge_work_storage_unavailable', status: 503 });

export function createManagedKeyStorage({ platform = process.platform, environment = process.env, spawnProcess = spawn, fileSystem = fs } = {}) {
  const prepare = async (operation, filename) => {
    if (!path.win32.isAbsolute(filename) || path.win32.normalize(filename) !== filename || !/^[A-Za-z]:\\/.test(filename)) throw unavailable();
    const systemRoot = environment.SystemRoot || 'C:\\Windows';
    if (!path.win32.isAbsolute(systemRoot) || !/^[A-Za-z]:\\/.test(systemRoot)) throw unavailable();
    const executable = path.win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    return new Promise((resolve, reject) => {
      const child = spawnProcess(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', Buffer.from(windowsPreparation, 'utf16le').toString('base64')], {
        windowsHide: true, shell: false, stdio: ['pipe', 'pipe', 'ignore'],
        env: { SystemRoot: systemRoot, WINDIR: systemRoot },
      });
      let output = ''; let ready = false; let failed = false; let closed = false; let writing = false; let acknowledged = false;
      let completeWrite; let rejectWrite; let writeResult;
      const fail = () => {
        if (failed || closed) return;
        clearTimeout(timer); failed = true; child.kill(); reject(unavailable()); rejectWrite?.(unavailable());
      };
      const timer = setTimeout(fail, 10_000); timer.unref?.();
      const file = {
        async writeFile(key) {
          if (writing || closed || failed || !Buffer.isBuffer(key) || key.length !== 32) { fail(); throw unavailable(); }
          writing = true;
          writeResult = new Promise((done, refuse) => { completeWrite = done; rejectWrite = refuse; });
          try { child.stdin.end(key); } catch { fail(); }
          return writeResult;
        },
        async sync() { if (!writeResult) throw unavailable(); await writeResult; },
        async close() { if (!writing) { fail(); return; } await writeResult.catch(() => {}); },
      };
      child.once('error', fail); child.stdin?.once('error', fail);
      child.stdout?.on('data', (chunk) => {
        if (failed || closed) return;
        output += chunk.toString('utf8'); if (output.length > 128) { fail(); return; }
        if (!ready && operation === 'create-file' && output === '{"created":true}\n') { ready = true; output = ''; resolve(file); }
        else if (ready && writing && output === '{"written":true}\n') acknowledged = true;
        else if (output.includes('\n') && !(operation !== 'create-file' && ['{"created":true}\n', '{"created":false}\n'].includes(output)) && output !== '{"created":false}\n') fail();
      });
      child.once('close', (code) => {
        clearTimeout(timer); if (failed) return;
        if (ready) {
          if (code !== 0 || !writing || !acknowledged || output !== '{"written":true}\n') { fail(); return; }
          closed = true; completeWrite(); return;
        }
        if (code !== 0 || !['{"created":true}\n', '{"created":false}\n'].includes(output)) { fail(); return; }
        closed = true; resolve(output === '{"created":true}\n');
      });
      const metadata = `${Buffer.from(windowsNativeStorage, 'utf8').toString('base64')}\n${JSON.stringify({ operation, path: filename })}\n`;
      if (operation === 'create-file') child.stdin.write(metadata); else child.stdin.end(metadata);
    }).catch(() => { throw unavailable(); });
  };
  return {
    async prepareDirectory(directory) {
      if (platform === 'win32') return prepare('directory', directory);
      await fileSystem.mkdir(directory, { recursive: true, mode: 0o700 });
    },
    async createFile(filename) {
      if (platform !== 'win32') return fileSystem.open(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      const file = await prepare('create-file', filename);
      if (file === false) throw Object.assign(new Error('key exists'), { code: 'EEXIST' });
      return file;
    },
    async verifyFile(filename) {
      if (platform === 'win32') await prepare('verify-file', filename);
    },
  };
}
