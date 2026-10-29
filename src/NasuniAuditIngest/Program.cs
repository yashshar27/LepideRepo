using CsvHelper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NasuniAuditIngest.Configuration;
using NasuniAuditIngest.Parsing;
using NasuniAuditIngest.Security;
using NasuniAuditIngest.Storage;
using Npgsql;

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
var host = builder.Build();
var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("NasuniAuditIngest");

try
{
    var config = host.Services.GetRequiredService<IConfiguration>();
    var env = host.Services.GetRequiredService<IHostEnvironment>();
    new LicenseGate(config, env).EnsureCollectionAllowed();

    var ingestion = config.GetSection("Ingestion").Get<IngestionOptions>() ?? new IngestionOptions();
    var connectionString = config.GetConnectionString("AuditDb");
    if (string.IsNullOrWhiteSpace(connectionString))
        throw new InvalidOperationException("ConnectionStrings:AuditDb is required.");

    var fileArg = GetArg(args, "--file") ?? throw new ArgumentException("Missing --file <path>.");
    var file = Path.GetFullPath(fileArg);
    var format = GetArg(args, "--format") ?? throw new ArgumentException("Missing --format jsonl|csv.");
    if (!File.Exists(file)) throw new FileNotFoundException("Input file not found.", file);

    var parser = new NasuniAuditParser(ingestion);
    var store = new PostgresAuditStore(connectionString);
    var lineNumber = 0;
    var inserted = 0;
    var duplicates = 0;
    var rejected = 0;

    foreach (var raw in await File.ReadAllLinesAsync(file))
    {
        lineNumber++;
        if (string.IsNullOrWhiteSpace(raw)) continue;

        try
        {
            var envelope = parser.Parse(raw, format);
            if (await store.InsertAsync(envelope, CancellationToken.None)) inserted++;
            else duplicates++;
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException or
                                   CsvHelperException or NpgsqlException or InvalidOperationException or OverflowException)
        {
            rejected++;
            logger.LogError(ex, "Record rejected at {File}:{LineNumber}; format={Format}",
                Path.GetFileName(file), lineNumber, format);
            // Production: persist raw record to quarantine before advancing source progress.
        }
    }

    logger.LogInformation(
        "Import complete. inserted={Inserted}; deduplicated={Duplicates}; rejected={Rejected}; format={Format}",
        inserted, duplicates, rejected, format);
    if (rejected > 0) Environment.ExitCode = 2;
}
catch (Exception ex)
{
    logger.LogCritical(ex, "Ingestion run failed.");
    Environment.ExitCode = 1;
}

static string? GetArg(string[] args, string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}
