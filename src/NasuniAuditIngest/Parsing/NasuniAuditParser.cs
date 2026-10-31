using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CsvHelper;
using CsvHelper.Configuration;
using NasuniAuditIngest.Configuration;
using NasuniAuditIngest.Models;

namespace NasuniAuditIngest.Parsing;

public sealed class NasuniAuditParser(IngestionOptions options)
{
    // Documented CSV fields: timestamp, category, event type, path/from,
    // new path/to, user, group, SID, share/export, volume type, client IP,
    // snapshot timestamp, shared link.
    public AuditEnvelope Parse(string rawRecord, string format)
    {
        if (Encoding.UTF8.GetByteCount(rawRecord) > options.MaxRecordBytes)
            throw new FormatException($"Record exceeds configured {options.MaxRecordBytes}-byte limit.");

        try
        {
            return format.ToLowerInvariant() switch
            {
                "jsonl" or "json" => ParseJson(rawRecord),
                "csv" => ParseCsv(rawRecord),
                _ => throw new FormatException($"Unsupported format '{format}'. Use jsonl or csv.")
            };
        }
        catch (Exception ex) when (ex is FormatException or JsonException or InvalidOperationException or OverflowException)
        {
            return ParseGenericFallback(rawRecord, format);
        }
    }

    private AuditEnvelope ParseJson(string raw)
    {
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("Expected a JSON object.");

        if (LooksLikeVendorSpecificPayload(root))
            return ParseGenericJson(raw);

        var eventType = RequiredString(root, "event_type");
        var timestamp = RequiredDouble(root, "timestamp");
        var sequence = OptionalUInt64(root, "sequence");
        var volume = OptionalString(root, "volume");
        var username = OptionalString(root, "username");
        var path = OptionalString(root, "path");
        var clientIp = OptionalString(root, "ipaddr");
        var protocol = OptionalString(root, "proto");
        var result = OptionalInt64(root, "result");

        var occurredAt = DateTimeOffset.FromUnixTimeMilliseconds(
            checked((long)Math.Round(timestamp * 1000d, MidpointRounding.AwayFromZero)));

        // Provisional key only: validate sequence semantics in the target version.
        var sourceKey = sequence.HasValue
            ? $"json:{volume ?? "unknown-volume"}:{sequence.Value}:{timestamp.ToString("R", CultureInfo.InvariantCulture)}"
            : null;

        var payload = JsonSerializer.Serialize(root);
        return Build(
            eventType, eventType, occurredAt, username,
            username is null ? null : "user", path, clientIp, "unknown",
            sequence, volume, sourceKey, payload,
            new Dictionary<string, object?> { ["proto"] = protocol, ["result"] = result },
            raw);
    }

    private AuditEnvelope ParseCsv(string raw)
    {
        using var reader = new StringReader(raw);
        var config = new CsvConfiguration(CultureInfo.InvariantCulture)
        {
            HasHeaderRecord = false,
            DetectColumnCountChanges = true,
            TrimOptions = TrimOptions.Trim
        };

        using var csv = new CsvReader(reader, config);
        if (!csv.Read())
            throw new FormatException("Empty CSV record.");

        if (csv.Parser.Count != 13)
            throw new FormatException($"Expected 13 CSV fields; received {csv.Parser.Count}.");

        var fields = new string?[13];
        for (var i = 0; i < fields.Length; i++)
            fields[i] = csv.GetField(i);

        DateTimeOffset? occurredAt = null;
        if (!string.IsNullOrWhiteSpace(fields[0]))
        {
            if (!DateTimeOffset.TryParse(fields[0], CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var parsed))
                throw new FormatException("CSV timestamp is not parseable.");
            occurredAt = parsed;
        }

        var eventName = fields[2];
        if (string.IsNullOrWhiteSpace(eventName))
            throw new FormatException("CSV event type (column 3) is required.");

        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["timestamp"] = fields[0],
            ["category"] = fields[1],
            ["event_type"] = eventName,
            ["path_from"] = fields[3],
            ["new_path_to"] = fields[4],
            ["user"] = fields[5],
            ["group"] = fields[6],
            ["sid"] = fields[7],
            ["share_export_name"] = fields[8],
            ["volume_type"] = fields[9],
            ["client_ip"] = fields[10],
            ["snapshot_timestamp"] = fields[11],
            ["shared_link"] = fields[12]
        });

        // CSV's documented fields do not contain a stable event ID; no automatic dedup.
        return Build(
            $"nasuni.audit.{Slug(eventName)}", eventName, occurredAt, fields[5],
            string.IsNullOrWhiteSpace(fields[5]) ? null : "user", fields[3], fields[10],
            "unknown", null, null, null, payload,
            new Dictionary<string, object?>
            {
                ["category"] = fields[1],
                ["group"] = fields[6],
                ["sid"] = fields[7],
                ["volume_type"] = fields[9],
                ["snapshot_timestamp"] = fields[11],
                ["shared_link"] = fields[12]
            },
            raw);
    }

    private AuditEnvelope Build(
        string eventType, string? action, DateTimeOffset? occurredAt,
        string? actorId, string? actorType, string? targetPath, string? clientIp,
        string outcome, ulong? sourceSequence, string? sourceVolume,
        string? sourceEventKey, string rawPayloadJson,
        Dictionary<string, object?> sourceMetadata, string rawRecord,
        string sourceTypeOverride = "nasuni")
    {
        using var payloadDocument = JsonDocument.Parse(rawPayloadJson);
        var wrapper = JsonSerializer.Serialize(new
        {
            source_payload = payloadDocument.RootElement.Clone(),
            source_metadata = sourceMetadata
        });

        return new AuditEnvelope(
            "1.0", Guid.NewGuid(),
            RequiredOption(options.TenantId, nameof(options.TenantId)),
            RequiredOption(options.SourceId, nameof(options.SourceId)),
            sourceTypeOverride,
            RequiredOption(options.SourceInstance, nameof(options.SourceInstance)),
            sourceEventKey, eventType, action, occurredAt, DateTimeOffset.UtcNow,
            actorId, actorType, targetPath,
            System.Net.IPAddress.TryParse(clientIp, out _) ? clientIp : null,
            outcome, sourceSequence, sourceVolume, wrapper, options.ParserVersion,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawRecord))).ToLowerInvariant());
    }

    private AuditEnvelope ParseGenericFallback(string rawRecord, string format)
    {
        return format.ToLowerInvariant() switch
        {
            "jsonl" or "json" => ParseGenericJson(rawRecord),
            "csv" => ParseGenericCsv(rawRecord),
            _ => throw new FormatException($"Unsupported format '{format}'. Use jsonl or csv.")
        };
    }

    private AuditEnvelope ParseGenericJson(string raw)
    {
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("Expected a JSON object.");

        var sourceType = GetFirstString(root, "component", "vendor", "source", "platform", "system", "device");
        var eventType = GetFirstString(root, "event_type", "event", "eventName", "action", "operation", "op", "type");
        var occurredAt = GetTimestamp(root);
        var actorId = GetFirstString(root, "username", "user", "actor", "principal", "user_name", "account");
        var actorType = GetFirstString(root, "user_type", "actor_type", "role");
        var targetPath = GetFirstString(root, "path", "target_path", "object", "object_path", "object_path", "location", "file", "new_path", "destination");
        var clientIp = GetFirstString(root, "ipaddr", "client_ip", "source_ip", "host_ip", "ip", "addr");
        var outcome = GetFirstString(root, "result", "status", "outcome", "result_code") ?? "unknown";
        var sourceSequence = GetNullableUInt64(root, "sequence", "event_id", "sequence_id");
        var sourceVolume = GetFirstString(root, "volume", "storage", "dataset", "share");
        var sourceKey = GetFirstString(root, "event_key", "source_event_key", "id", "identifier");
        var provider = string.IsNullOrWhiteSpace(sourceType) ? "generic" : sourceType.Trim();
        var metadata = new Dictionary<string, object?>();
        foreach (var property in root.EnumerateObject())
            metadata[property.Name] = property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString(),
                JsonValueKind.Number => property.Value.TryGetInt64(out var l) ? l : property.Value.TryGetUInt64(out var u) ? u : property.Value.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null,
                _ => property.Value.ToString()
            };

        return Build(
            string.IsNullOrWhiteSpace(eventType) ? "GENERIC_EVENT" : eventType,
            string.IsNullOrWhiteSpace(eventType) ? "GENERIC_EVENT" : eventType,
            occurredAt,
            actorId,
            actorType,
            targetPath,
            clientIp,
            outcome,
            sourceSequence,
            sourceVolume,
            sourceKey,
            raw,
            metadata,
            raw,
            provider);
    }

    private AuditEnvelope ParseGenericCsv(string raw)
    {
        var fields = SplitCsvLine(raw);
        if (fields.Count < 4)
            throw new FormatException("CSV record does not contain enough fields for generic fallback parsing.");

        var timestamp = TryParseTimestamp(fields[0]) ?? DateTimeOffset.UtcNow;
        var component = fields.Count > 1 ? fields[1].Trim() : "generic";
        var eventType = fields.Count > 2 ? fields[2].Trim() : "GENERIC_EVENT";
        var targetPath = fields.Count > 3 ? fields[3].Trim() : null;
        var actorId = fields.Count > 4 ? fields[4].Trim() : null;
        var clientIp = fields.Count > 5 ? fields[5].Trim() : null;
        var outcome = fields.Count > 6 ? fields[6].Trim() : "unknown";

        var metadata = new Dictionary<string, object?>
        {
            ["raw_csv_fields"] = fields
        };

        return Build(
            string.IsNullOrWhiteSpace(eventType) ? "GENERIC_EVENT" : eventType,
            string.IsNullOrWhiteSpace(eventType) ? "GENERIC_EVENT" : eventType,
            timestamp,
            string.IsNullOrWhiteSpace(actorId) ? null : actorId,
            null,
            string.IsNullOrWhiteSpace(targetPath) ? null : targetPath,
            string.IsNullOrWhiteSpace(clientIp) ? null : clientIp,
            string.IsNullOrWhiteSpace(outcome) ? "unknown" : outcome,
            null,
            null,
            null,
            raw,
            metadata,
            raw,
            string.IsNullOrWhiteSpace(component) ? "generic" : component);
    }

    private static DateTimeOffset? GetTimestamp(JsonElement root)
    {
        var candidate = GetFirstString(root, "timestamp", "time", "event_time", "created_at", "occurred_at")
            ?? GetFirstDoubleString(root, "timestamp", "time", "event_time", "created_at", "occurred_at");

        if (string.IsNullOrWhiteSpace(candidate))
            return DateTimeOffset.UtcNow;

        if (DateTimeOffset.TryParse(candidate, out var dto))
            return dto;

        if (double.TryParse(candidate, NumberStyles.Float, CultureInfo.InvariantCulture, out var unixSeconds))
            return DateTimeOffset.FromUnixTimeSeconds((long)Math.Round(unixSeconds));

        return DateTimeOffset.UtcNow;
    }

    private static string? GetFirstString(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (root.TryGetProperty(name, out var value))
            {
                return value.ValueKind switch
                {
                    JsonValueKind.String => value.GetString(),
                    JsonValueKind.Number => value.GetDouble().ToString(CultureInfo.InvariantCulture),
                    JsonValueKind.True => bool.TrueString,
                    JsonValueKind.False => bool.FalseString,
                    JsonValueKind.Null => null,
                    _ => value.GetRawText()
                };
            }
        }

        return null;
    }

    private static string? GetFirstDoubleString(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
                if (root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var numericValue))
                    return numericValue.ToString(CultureInfo.InvariantCulture);
        }

        return null;
    }

    private static ulong? GetNullableUInt64(JsonElement root, params string[] names)
    {
        foreach (var name in names)
        {
            if (root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetUInt64(out var number))
                return number;
        }

        return null;
    }

    private static DateTimeOffset? TryParseTimestamp(string value)
    {
        var trimmed = value.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
            return null;

        if (DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto))
            return dto;

        if (double.TryParse(trimmed, NumberStyles.Float, CultureInfo.InvariantCulture, out var unixSeconds))
            return DateTimeOffset.FromUnixTimeSeconds((long)Math.Round(unixSeconds));

        return null;
    }

    private static List<string> SplitCsvLine(string line)
    {
        var result = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (ch == ',' && !inQuotes)
            {
                result.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(ch);
            }
        }

        result.Add(current.ToString());
        return result.Select(v => v.Trim()).ToList();
    }

    private static bool LooksLikeVendorSpecificPayload(JsonElement root)
    {
        foreach (var name in new[] { "component", "vendor", "source", "platform", "system", "device" })
        {
            if (!root.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
                continue;

            if (value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();
                if (!string.IsNullOrWhiteSpace(text) && !text.Equals("nasuni", StringComparison.OrdinalIgnoreCase))
                    return true;
                continue;
            }

            return true;
        }

        return false;
    }

    private static string RequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(value.GetString()))
            throw new FormatException($"Required JSON string '{name}' is missing.");
        return value.GetString()!;
    }

    private static double RequiredDouble(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value) || !value.TryGetDouble(out var number) ||
            double.IsNaN(number) || double.IsInfinity(number))
            throw new FormatException($"Required numeric JSON field '{name}' is missing or invalid.");
        return number;
    }

    private static string? OptionalString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : null;

    private static ulong? OptionalUInt64(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number &&
        value.TryGetUInt64(out var number) ? number : null;

    private static long? OptionalInt64(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt64(out var number) ? number : null;

    private static string RequiredOption(string value, string name) =>
        string.IsNullOrWhiteSpace(value)
            ? throw new InvalidOperationException($"Configuration Ingestion:{name} is required.")
            : value;

    private static string Slug(string value) =>
        string.Join('.', new string(value.ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) ? c : '.').ToArray())
            .Split('.', StringSplitOptions.RemoveEmptyEntries));
}
