namespace NasuniAuditIngest.Listening;

public sealed record AuditLogEntry
{
    public DateTimeOffset When { get; init; } = DateTimeOffset.UtcNow;
    public string ServerName { get; init; } = "";
    public string Who { get; init; } = "";
    public string ObjectName { get; init; } = "";
    public string ObjectPath { get; init; } = "";
    public string Operation { get; init; } = "";
    public string ProcessName { get; init; } = "";
    public string From { get; init; } = "";
    public string What { get; init; } = "";
    public string RawMessage { get; init; } = "";
}
