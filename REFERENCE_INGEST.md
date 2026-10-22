# Reference ingest (SuperWagie patch)

WeKnora Lite v0.8.3 plus a reference-ingest patch. A document can be
registered by absolute path: the backend reads the file where it lives and
writes no copy. Everything else (parse, chunks, embeddings, search, preview)
is the upstream code path.

## Files in the patch

| File | Change |
| --- | --- |
| `internal/utils/refpath.go` | `ref://` helpers, `ValidateReferencePath` (absolute, regular file, not a symlink) |
| `internal/application/service/knowledge_ref.go` | `CreateKnowledgeFromPath`: validate, hash, create row, enqueue parse, audit |
| `internal/handler/knowledge_ref.go` | `POST .../knowledge/ref` |
| `internal/application/service/file/local.go` | ref reads open the source; delete is a no-op; a ref is a valid copy source |
| `internal/application/repository/knowledge.go` | lookup by `file_path` (idempotency) |
| `internal/types/interfaces/knowledge.go` | service + repository methods |
| `internal/router/routes_knowledge.go` | route in the existing ingest group |
| `local_ref_test.go`, `knowledge_ref_test.go` | unit tests |

## Build

```bash
export EDITION=lite CGO_ENABLED=1
export CGO_CFLAGS="-Wno-deprecated-declarations"
export CGO_LDFLAGS="-Wl,-no_warn_duplicate_libraries"   # macOS only
go build -tags "sqlite_fts5" -o WeKnora-lite ./cmd/server
```

The binary reads `config/` and `migrations/sqlite/` from the working
directory (or the tarball layout), exactly like the upstream release. The
patched `config/config.yaml` binds `127.0.0.1:17808`, not upstream's
`0.0.0.0:8080`, so a local WeKnora install on 8080 is never adopted or
collided with. `SERVER_PORT` / `SERVER_HOST` still override it.

## API

```
POST /api/v1/knowledge-bases/:kb/knowledge/ref
Authorization: Bearer <jwt>   or   X-API-Key: <scoped key with ingest>
Content-Type: application/json

{
  "path": "/Users/me/notes/meeting.md",   // required, absolute, existing, not a symlink
  "title": "meeting.md",                   // default: base name
  "folder_path": "superwagie/proj/docs",   // optional, the UI folder tree
  "metadata": { "sw_document_id": "..." },
  "tag_ids": [],
  "channel": "api",
  "process_config": null
}
```

Response: `{ "success": true, "data": <Knowledge> }` with
`file_path: "ref://<absolute path>"`, `file_size`, `file_hash`,
`parse_status: "pending"`.

Semantics:

- **Idempotent per (knowledge base, path).** The same path returns the existing
  row and does not reparse.
- **Change.** Edit the file, then call the existing
  `POST /api/v1/knowledge/:id/reparse`. The knowledge id survives, so citations
  stay valid. Reparse re-reads the file at its path.
- **Delete.** `DELETE /api/v1/knowledge/:id` removes the row and chunks; the
  source file is never touched.
- **Preview.** `GET /api/v1/knowledge/:id/preview` streams the current source
  file.
- **Size limit.** `MAX_FILE_SIZE_MB` (50 by default), same as upload.
- **Clone.** Copying a knowledge base materialises ref rows as real copies.

## Verified on 2026-10-22 (macOS arm64, sqlite lite)

- Unit tests pass:
  - `go test -tags sqlite_fts5 ./internal/application/service/ -run TestCreateKnowledgeFromPath`
  - `go test -tags sqlite_fts5 ./internal/application/service/file/ -run 'Reference|CloningAReference'`
- End to end against a throwaway instance with a fake OpenAI-compatible
  embeddings endpoint:
  - register → `parse_status=completed`, one chunk with the file's text;
  - hybrid search returns the chunk, `knowledge_title`/`knowledge_filename` and
    custom metadata intact;
  - edit file + reparse → same knowledge id, chunk content updated,
    preview streams the new bytes;
  - delete knowledge → row gone, **source file still exists**;
  - `data/files` after the whole run: **0 bytes** — no corpus copy;
  - works with a scoped API key (`retrieve` + `ingest`).

## Limits

- Targets Lite/SQLite. The standard edition's `file_path` column is shorter.
- No configurable reference-root allow-list: the guard is loopback binding, the
  API key, and per-path validation (absolute, regular file, no symlink).
- HTTP only; no CLI subcommand for ref ingest.
- A file removed from disk leaves the knowledge row in place (parse makes it
  `failed` on reparse); the caller owns "missing" state.
