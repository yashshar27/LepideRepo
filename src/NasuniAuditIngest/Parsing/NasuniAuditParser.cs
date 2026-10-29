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

        return format.ToLowerInvariant() switch
        {
            "jsonl" or "json" => ParseJson(rawRecord),
            "csv" => ParseCsv(rawRecord),
            _ => throw new FormatException($"Unsupported format '{format}'. Use jsonl or csv.")
        };
    }

    private AuditEnvelope ParseJson(string raw)
    {
        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("Expected a JSON object.");

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
        Dictionary<string, object?> sourceMetadata, string rawRecord)
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
            "nasuni",
            RequiredOption(options.SourceInstance, nameof(options.SourceInstance)),
            sourceEventKey, eventType, action, occurredAt, DateTimeOffset.UtcNow,
            actorId, actorType, targetPath,
            System.Net.IPAddress.TryParse(clientIp, out _) ? clientIp : null,
            outcome, sourceSequence, sourceVolume, wrapper, options.ParserVersion,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawRecord))).ToLowerInvariant());
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
