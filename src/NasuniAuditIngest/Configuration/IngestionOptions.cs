namespace NasuniAuditIngest.Configuration;

public sealed class IngestionOptions
{
    public string TenantId { get; set; } = "";
    public string SourceId { get; set; } = "";
    public string SourceInstance { get; set; } = "";
    public string CollectorVersion { get; set; } = "0.1.0";
    public string ParserVersion { get; set; } = "0.1.0";
    public int MaxRecordBytes { get; set; } = 262144;
}
