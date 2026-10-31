using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace NasuniAuditIngest.Listening;

public sealed class SyslogListenerService(AuditLogStore store)
{
    private readonly object _sync = new();
    private CancellationTokenSource? _cts;
    private Task? _listenerTask;
    private bool _isRunning;
    private readonly Random _random = new();

    public bool IsRunning => _isRunning;

    public void Start()
    {
        lock (_sync)
        {
            if (_isRunning)
                return;

            _cts = new CancellationTokenSource();
            _listenerTask = Task.Run(() => ListenLoop(_cts.Token), _cts.Token);
            _isRunning = true;
        }
    }

    public void Stop()
    {
        lock (_sync)
        {
            if (!_isRunning)
                return;

            _cts?.Cancel();
            _listenerTask?.Wait(250);
            _isRunning = false;
        }
    }

    private async Task ListenLoop(CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(1514);
        udp.Client.ReceiveTimeout = 500;

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var result = await udp.ReceiveAsync(cancellationToken);
                var message = Encoding.UTF8.GetString(result.Buffer);
                if (!string.IsNullOrWhiteSpace(message))
                    store.Add(SyslogEventParser.Parse(message));
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                // Keep the listener alive even when no packet is received.
                await Task.Delay(250, cancellationToken);
            }
        }
    }

    public static IReadOnlyList<AuditLogEntry> LoadSampleEntries(string? samplePath = null)
    {
        var resolvedPath = samplePath ?? Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            "samples", "nasuni-jsonl.log");

        if (!File.Exists(resolvedPath))
            return Array.Empty<AuditLogEntry>();

        var entries = new List<AuditLogEntry>();
        foreach (var rawLine in File.ReadLines(resolvedPath))
        {
            if (string.IsNullOrWhiteSpace(rawLine))
                continue;

            try
            {
                using var doc = JsonDocument.Parse(rawLine);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    continue;

                var timestamp = root.TryGetProperty("timestamp", out var tsValue) && tsValue.TryGetDouble(out var unixSeconds)
                    ? DateTimeOffset.FromUnixTimeSeconds((long)Math.Round(unixSeconds))
                    : DateTimeOffset.UtcNow;

                var eventType = root.TryGetProperty("event_type", out var eventTypeValue) && eventTypeValue.ValueKind == JsonValueKind.String
                    ? eventTypeValue.GetString() ?? "N/A"
                    : "N/A";

                var username = root.TryGetProperty("username", out var usernameValue) && usernameValue.ValueKind == JsonValueKind.String
                    ? usernameValue.GetString()
                    : null;

                var path = root.TryGetProperty("path", out var pathValue) && pathValue.ValueKind == JsonValueKind.String
                    ? pathValue.GetString()
                    : null;

                var ip = root.TryGetProperty("ipaddr", out var ipValue) && ipValue.ValueKind == JsonValueKind.String
                    ? ipValue.GetString()
                    : null;

                var protocol = root.TryGetProperty("proto", out var protoValue) && protoValue.ValueKind == JsonValueKind.String
                    ? protoValue.GetString()
                    : "nasuni";

                entries.Add(new AuditLogEntry
                {
                    When = timestamp,
                    ServerName = "nasuni-edge-01",
                    Who = string.IsNullOrWhiteSpace(username) ? "N/A" : username,
                    ObjectName = string.IsNullOrWhiteSpace(path) ? "N/A" : Path.GetFileName(path),
                    ObjectPath = string.IsNullOrWhiteSpace(path) ? "N/A" : path,
                    Operation = string.IsNullOrWhiteSpace(eventType) ? "N/A" : eventType,
                    ProcessName = string.IsNullOrWhiteSpace(protocol) ? "nasuni" : protocol,
                    From = string.IsNullOrWhiteSpace(ip) ? "N/A" : ip,
                    What = string.IsNullOrWhiteSpace(eventType) ? "N/A" : eventType,
                    RawMessage = rawLine
                });
            }
            catch (JsonException)
            {
                // Ignore unreadable lines; keep the UI focused on valid events.
            }
        }

        return entries;
    }

    public void AddSampleData()
    {
        var sampleEntries = LoadSampleEntries();
        if (sampleEntries.Count > 0)
        {
            foreach (var entry in sampleEntries)
                store.Add(entry);
            return;
        }

        var names = new[] { "alice", "bob", "carol", "dana" };
        var ops = new[] { "READ", "WRITE", "DELETE", "MODIFY" };
        var paths = new[]
        {
            "/data/files/report.pdf",
            "/data/exports/summary.csv",
            "/shares/finance/q4-budget.xlsx",
            "/archive/backups/server-01.zip"
        };
        var sources = new[] { "10.10.9.12", "10.10.9.18", "10.10.9.42" };

        var fallbackEntry = new AuditLogEntry
        {
            When = DateTimeOffset.UtcNow,
            ServerName = "nasuni-edge-01",
            Who = names[_random.Next(names.Length)],
            Operation = ops[_random.Next(ops.Length)],
            ObjectName = Path.GetFileName(paths[_random.Next(paths.Length)]),
            ObjectPath = paths[_random.Next(paths.Length)],
            ProcessName = "nasuni-filer",
            From = sources[_random.Next(sources.Length)],
            What = "audit event",
            RawMessage = "sample syslog event"
        };

        store.Add(fallbackEntry);
    }
}
