namespace NasuniAuditIngest.Models;

public sealed class NasuniAuthRequest
{
    public string NmcHostname { get; set; } = "";
    public string NmcUsername { get; set; } = "";
    public string NmcPassword { get; set; } = "";
    public string EdgeHostname { get; set; } = "";
    public int EdgePort { get; set; } = 443;
}
