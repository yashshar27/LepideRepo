# Nasuni Audit Ingestion — first vertical slice

A C#/.NET 8 starter that parses documented-format Nasuni sample audit records and writes normalized records to PostgreSQL.

## Scope and limitations

Included:
- JSON-lines parser for the documented Nasuni JSON audit-event shape.
- CSV parser for the documented 13-column Nasuni audit-log shape.
- Versioned normalized event envelope.
- PostgreSQL persistence and a provisional source-derived key for JSON events.
- Local-only development license gate.
- Sample fixtures, Docker Compose PostgreSQL, and parser tests.

Not included yet:
- A live Syslog socket listener.
- Production license verification.
- Durable queue/checkpoint/replay.
- A production-grade tamper-evident audit store.

This is intentional. Confirm the actual Syslog transport and messages from the target Nasuni deployment before implementing live collection.

## Requirements

- .NET SDK 8.x
- Docker Desktop or PostgreSQL 16
- `psql` or a PostgreSQL GUI to apply the schema

## 1. Start PostgreSQL

```bash
docker compose up -d postgres
```

Local-only credentials:
- Host `localhost`, port `5432`
- Database `audit_ingestion`
- User `audit_app`
- Password `local_dev_only_change_me`

Do not use these credentials outside local development.

## 2. Create the schema

PowerShell:
```powershell
$env:PGPASSWORD = "local_dev_only_change_me"
psql -h localhost -p 5432 -U audit_app -d audit_ingestion -f sql/001_init.sql
```

Bash:
```bash
PGPASSWORD=local_dev_only_change_me psql -h localhost -p 5432 -U audit_app -d audit_ingestion -f sql/001_init.sql
```

## 3. Set local environment variables

PowerShell:
```powershell
$env:DOTNET_ENVIRONMENT = "Development"
$env:ConnectionStrings__AuditDb = "Host=localhost;Port=5432;Database=audit_ingestion;Username=audit_app;Password=local_dev_only_change_me"
$env:Ingestion__TenantId = "tenant-dev-001"
$env:Ingestion__SourceId = "nasuni-edge-lab-001"
$env:Ingestion__SourceInstance = "nasuni-edge-lab"
$env:License__Mode = "development"
```

Bash:
```bash
export DOTNET_ENVIRONMENT=Development
export ConnectionStrings__AuditDb='Host=localhost;Port=5432;Database=audit_ingestion;Username=audit_app;Password=local_dev_only_change_me'
export Ingestion__TenantId='tenant-dev-001'
export Ingestion__SourceId='nasuni-edge-lab-001'
export Ingestion__SourceInstance='nasuni-edge-lab'
export License__Mode='development'
```

Development license mode is a local test gate only. It is not a real license verifier and refuses to run outside the Development environment.

## 4. Build and test

```bash
dotnet restore src/NasuniAuditIngest/NasuniAuditIngest.csproj
dotnet build src/NasuniAuditIngest/NasuniAuditIngest.csproj
dotnet test tests/NasuniAuditIngest.Tests/NasuniAuditIngest.Tests.csproj
```

## 5. Import sample records

```bash
dotnet run --project src/NasuniAuditIngest -- --file samples/nasuni-jsonl.log --format jsonl
dotnet run --project src/NasuniAuditIngest -- --file samples/nasuni-csv.log --format csv
```

The sample records are synthetic and illustrate documented field shapes. They are not a promise that every Nasuni version emits identical messages.

Supported file formats:
- `jsonl`: one JSON audit object per line.
- `csv`: one 13-field CSV record per line, without a header.

This importer does not strip a Syslog PRI/header or guess message framing. If actual Syslog wraps JSON/CSV, preserve a sanitized sample and add a tested framing adapter after verifying the deployed format.

## 6. Verify persisted rows

```sql
SELECT event_id, source_id, source_event_key, event_type,
       occurred_at, actor_id, target_path, outcome
FROM audit_events
ORDER BY ingested_at DESC
LIMIT 20;
```

Check JSON-key duplicates:
```sql
SELECT tenant_id, source_id, source_event_key, COUNT(*)
FROM audit_events
WHERE source_event_key IS NOT NULL
GROUP BY tenant_id, source_id, source_event_key
HAVING COUNT(*) > 1;
```

## Important correctness limitations

1. Decide the queue's durability/restart behavior. An in-memory queue is not durable.
2. Add quarantine persistence and controlled replay.
3. Add source-specific checkpoints/acknowledgement only after the real collection mechanism is confirmed.
4. `result` is preserved but outcome remains `unknown` until its semantics are verified for the deployed version.
5. `sequence` is documented as a rotating incrementing event ID. The provisional JSON deduplication key combines configured source, volume, sequence and timestamp; validate this in the target environment.
6. The documented CSV field list has no stable event identifier, so CSV rows are not automatically deduplicated. This avoids collapsing distinct but identical-looking operations.
7. Add a real Syslog listener only after confirming transport (UDP/TCP/TLS), sender authentication, framing and actual payload format.
