namespace NasuniAuditIngest.Models;

public sealed record AuditEnvelope(
    string SchemaVersion,
    Guid EventId,
    string TenantId,
    string SourceId,
    string SourceType,
    string SourceInstance,
    string? SourceEventKey,
    string EventType,
    string? Action,
    DateTimeOffset? OccurredAt,
    DateTimeOffset ObservedAt,
    string? ActorId,
    string? ActorType,
    string? TargetPath,
    string? ClientIp,
    string Outcome,
    ulong? SourceSequence,
    string? SourceVolume,
    string RawPayloadJson,
    string ParserVersion,
    string RawRecordSha256);
