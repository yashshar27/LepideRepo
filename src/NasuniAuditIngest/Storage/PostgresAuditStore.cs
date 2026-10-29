using Npgsql;
using NasuniAuditIngest.Models;

namespace NasuniAuditIngest.Storage;

public sealed class PostgresAuditStore(string connectionString)
{
    public async Task<bool> InsertAsync(AuditEnvelope e, CancellationToken cancellationToken)
    {
        const string sql = """
INSERT INTO audit_events (
    event_id, schema_version, tenant_id, source_id, source_type, source_instance,
    source_event_key, event_type, action, occurred_at, observed_at, actor_id,
    actor_type, target_path, client_ip, outcome, source_sequence, source_volume,
    raw_payload, parser_version, raw_record_sha256
) VALUES (
    @event_id, @schema_version, @tenant_id, @source_id, @source_type, @source_instance,
    @source_event_key, @event_type, @action, @occurred_at, @observed_at, @actor_id,
    @actor_type, @target_path, @client_ip, @outcome, @source_sequence, @source_volume,
    @raw_payload::jsonb, @parser_version, @raw_record_sha256
)
ON CONFLICT (tenant_id, source_id, source_event_key)
    WHERE source_event_key IS NOT NULL
DO NOTHING
RETURNING event_id;
""";

        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var cmd = new NpgsqlCommand(sql, connection);

        cmd.Parameters.AddWithValue("event_id", e.EventId);
        cmd.Parameters.AddWithValue("schema_version", e.SchemaVersion);
        cmd.Parameters.AddWithValue("tenant_id", e.TenantId);
        cmd.Parameters.AddWithValue("source_id", e.SourceId);
        cmd.Parameters.AddWithValue("source_type", e.SourceType);
        cmd.Parameters.AddWithValue("source_instance", e.SourceInstance);
        cmd.Parameters.AddWithValue("source_event_key", (object?)e.SourceEventKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("event_type", e.EventType);
        cmd.Parameters.AddWithValue("action", (object?)e.Action ?? DBNull.Value);
        cmd.Parameters.AddWithValue("occurred_at", (object?)e.OccurredAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("observed_at", e.ObservedAt);
        cmd.Parameters.AddWithValue("actor_id", (object?)e.ActorId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("actor_type", (object?)e.ActorType ?? DBNull.Value);
        cmd.Parameters.AddWithValue("target_path", (object?)e.TargetPath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("client_ip", (object?)e.ClientIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("outcome", e.Outcome);
        cmd.Parameters.AddWithValue("source_sequence",
            e.SourceSequence.HasValue ? (object)(decimal)e.SourceSequence.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("source_volume", (object?)e.SourceVolume ?? DBNull.Value);
        cmd.Parameters.AddWithValue("raw_payload", e.RawPayloadJson);
        cmd.Parameters.AddWithValue("parser_version", e.ParserVersion);
        cmd.Parameters.AddWithValue("raw_record_sha256", e.RawRecordSha256);

        var result = await cmd.ExecuteScalarAsync(cancellationToken);
        return result is not null;
    }
}
