// CI-only normal creation diagnostics. Never print stdin, argv, paths or child
// diagnostics. The temporary injection emits only a fixed stage vocabulary.
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { createManagedKeyStorage } from './fixtures/managed-key-storage.mjs';

if (process.platform !== 'win32') throw new Error('native Windows is required');
const started = performance.now();
const events = [];
const record = (stage) => events.push({ stage, elapsed_ms: Math.round(performance.now() - started) });
const allowed = new Set(['boot', 'stdin_open', 'source_line', 'source_read', 'metadata_line', 'module_start', 'module_ready', 'metadata_read', 'path_valid', 'compile_start', 'compile_done', 'run_done', 'caught', 'IOException', 'UnauthorizedAccessException', 'Win32Exception', 'TypeLoadException', 'ArgumentException', 'NullReferenceException', 'InvalidOperationException', 'RuntimeException', 'MethodInvocationException']);
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'managed-normal-diagnostic-'));
let success = false;
const storage = createManagedKeyStorage({
  spawnProcess(executable, args, options) {
    let script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    const marker = (stage) => `[Console]::Error.WriteLine('UH_PHASE_${stage}')`;
    const replacements = [
      ["try {\n  $stdin", `try {\n  ${marker('boot')}\n  $stdin`],
      ["  function ReadBoundedLine", `  ${marker('stdin_open')}\n  function ReadBoundedLine`],
      ["  $source =", `  ${marker('source_line')}\n  $source =`],
      ["  $metadataLine =", `  ${marker('source_read')}\n  $metadataLine =`],
      ["  Import-Module -Name", `  ${marker('metadata_line')}\n  ${marker('module_start')}\n  Import-Module -Name`],
      ["  $inputValue =", `  ${marker('module_ready')}\n  $inputValue =`],
      ["  if (@($inputValue", `  ${marker('metadata_read')}\n  if (@($inputValue`],
      ["  Add-Type -TypeDefinition", `  ${marker('path_valid')}\n  ${marker('compile_start')}\n  Add-Type -TypeDefinition`],
      ["  [ManagedPrivateStorage]::Run", `  ${marker('compile_done')}\n  [ManagedPrivateStorage]::Run`],
      ["} catch {\n", `  ${marker('run_done')}\n} catch {\n  ${marker('caught')}\n  $failure = $_.Exception\n  while ($null -ne $failure) { [Console]::Error.WriteLine('UH_PHASE_' + $failure.GetType().Name); $failure = $failure.InnerException }\n`],
    ];
    for (const [needle, replacement] of replacements) {
      if (script.split(needle).length !== 2) throw new Error('diagnostic bootstrap identity differs');
      script = script.replace(needle, replacement);
    }
    record('spawn');
    const child = spawn(executable, [...args.slice(0, -1), Buffer.from(script, 'utf16le').toString('base64')], { ...options, stdio: ['pipe', 'pipe', 'pipe'] });
    let pending = '';
    child.stderr.on('data', (chunk) => {
      pending = (pending + chunk.toString('utf8')).slice(-4096);
      for (const line of pending.split(/\r?\n/).slice(0, -1)) {
        const match = /^UH_PHASE_([A-Za-z_]+)$/.exec(line);
        if (match && allowed.has(match[1]) && events.length < 100) record(match[1]);
      }
      pending = pending.split(/\r?\n/).at(-1);
    });
    child.once('exit', (code) => record(code === 0 ? 'exit_zero' : 'exit_nonzero'));
    return child;
  },
});
try {
  await storage.prepareDirectory(path.join(temporary, 'private'));
  success = true;
} catch { record('storage_refused'); }
finally {
  await fs.rm(temporary, { recursive: true, force: true });
  const result = { schema: 1, native_windows: true, success, provider_operations: false, events };
  const output = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'managed-key-native-phase-diagnostic.json');
  await fs.writeFile(output, JSON.stringify(result, null, 2) + '\n');
  process.stdout.write(JSON.stringify(result) + '\n');
}
