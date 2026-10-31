using System.Globalization;
using System.Text.RegularExpressions;

namespace NasuniAuditIngest.Listening;

public static partial class SyslogEventParser
{
    public static AuditLogEntry Parse(string rawMessage)
    {
        if (string.IsNullOrWhiteSpace(rawMessage))
            throw new FormatException("Syslog message cannot be empty.");

        var normalized = rawMessage.Trim();
        var prefixIndex = normalized.IndexOf('>');
        if (prefixIndex >= 0)
            normalized = normalized[(prefixIndex + 1)..].Trim();

        var headerMatch = HeaderPattern().Match(normalized);
        var serverName = headerMatch.Success ? headerMatch.Groups["host"].Value : "nasuni-local";
        var remaining = headerMatch.Success ? headerMatch.Groups["rest"].Value : normalized;

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in KeyValuePattern().Matches(remaining))
        {
            var key = match.Groups["key"].Value;
            var value = match.Groups["value"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(key))
                values[key] = value.Trim('"');
        }

        var who = values.TryGetValue("user", out var user) ? user : "unknown";
        var operation = values.TryGetValue("op", out var op) ? op : values.TryGetValue("operation", out var opAlt) ? opAlt : "READ";
        var objectPath = values.TryGetValue("path", out var path) ? path : values.TryGetValue("object", out var obj) ? obj : "/unknown";
        var from = values.TryGetValue("src", out var src) ? src : values.TryGetValue("from", out var fromHost) ? fromHost : "unknown";
        var process = values.TryGetValue("proc", out var proc) ? proc : values.TryGetValue("process", out var processName) ? processName : "nasuni";
        var operationName = operation.ToUpperInvariant();
        var objectName = Path.GetFileName(objectPath);
        var what = values.TryGetValue("what", out var whatValue) ? whatValue : operationName;

        var when = headerMatch.Success
            ? ParseTimestamp(headerMatch.Groups["month"].Value, headerMatch.Groups["day"].Value, headerMatch.Groups["time"].Value)
            : DateTimeOffset.UtcNow;

        return new AuditLogEntry
        {
            When = when,
            ServerName = serverName,
            Who = who,
            ObjectName = objectName,
            ObjectPath = objectPath,
            Operation = operationName,
            ProcessName = process,
            From = from,
            What = what,
            RawMessage = rawMessage
        };
    }

    private static DateTimeOffset ParseTimestamp(string month, string day, string time)
    {
        var now = DateTimeOffset.UtcNow;
        if (!int.TryParse(day, out var dayNumber)) dayNumber = now.Day;

        var monthNumber = DateTime.ParseExact(month, "MMM", CultureInfo.InvariantCulture).Month;
        var parsed = new DateTime(now.Year, monthNumber, dayNumber,
            int.Parse(time.Split(':')[0]), int.Parse(time.Split(':')[1]), int.Parse(time.Split(':')[2]), DateTimeKind.Utc);

        return new DateTimeOffset(parsed, TimeSpan.Zero);
    }

    [GeneratedRegex("^(?<month>[A-Z][a-z]{2})\\s+(?<day>\\d{1,2})\\s+(?<time>\\d{2}:\\d{2}:\\d{2})\\s+(?<host>\\S+)\\s+(?<rest>.*)$")]
    private static partial Regex HeaderPattern();

    [GeneratedRegex("(?<key>[A-Za-z0-9_-]+)=(?<value>\"[^\"]*\"|[^\\s]+)")]
    private static partial Regex KeyValuePattern();
}
