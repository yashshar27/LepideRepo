using System.Net;

namespace NasuniAuditIngest.Configuration;

public sealed class IngestionOptions
{
    public string TenantId { get; set; } = "";
    public string SourceId { get; set; } = "";
    public string SourceInstance { get; set; } = "";
    public string CollectorVersion { get; set; } = "0.1.0";
    public string ParserVersion { get; set; } = "0.1.0";
    public int MaxRecordBytes { get; set; } = 262144;

    public string NmcHostname { get; set; } = "";
    public string NmcUsername { get; set; } = "";
    public string NmcPassword { get; set; } = "";

    public string EdgeHostname { get; set; } = "";
    public int EdgePort { get; set; } = 443;

    public void ValidateAuthentication()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(NmcHostname))
            errors.Add("NmcHostname is required.");
        else if (!IsValidHostOrIp(NmcHostname))
            errors.Add("NmcHostname must be a valid IPv4/IPv6 address or hostname.");

        if (string.IsNullOrWhiteSpace(NmcUsername))
            errors.Add("NmcUsername is required.");

        if (string.IsNullOrWhiteSpace(NmcPassword))
            errors.Add("NmcPassword is required.");

        if (string.IsNullOrWhiteSpace(EdgeHostname))
            errors.Add("EdgeHostname is required.");
        else if (!IsValidHostOrIp(EdgeHostname))
            errors.Add("EdgeHostname must be a valid IPv4/IPv6 address or hostname.");

        if (EdgePort < 1 || EdgePort > 65535)
            errors.Add("EdgePort must be between 1 and 65535.");

        if (errors.Count > 0)
            throw new InvalidOperationException(string.Join("; ", errors));
    }

    public static bool IsValidHostOrIp(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var candidate = value.Trim();
        if (IPAddress.TryParse(candidate, out _))
            return true;

        var hostType = Uri.CheckHostName(candidate);
        return hostType is UriHostNameType.Dns or UriHostNameType.IPv4 or UriHostNameType.IPv6;
    }
}
