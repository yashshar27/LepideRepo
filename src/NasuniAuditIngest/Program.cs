using CsvHelper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NasuniAuditIngest.Configuration;
using NasuniAuditIngest.Listening;
using NasuniAuditIngest.Models;
using NasuniAuditIngest.Parsing;
using NasuniAuditIngest.Security;
using NasuniAuditIngest.Storage;
using Npgsql;

if (args.Contains("--file"))
{
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
}
else
{
    var builder = WebApplication.CreateBuilder(args);
    builder.Logging.ClearProviders();
    builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
    builder.Services.AddSingleton<AuditLogStore>();
    builder.Services.AddSingleton<SyslogListenerService>();

    var app = builder.Build();
    var logStore = app.Services.GetRequiredService<AuditLogStore>();

    app.MapGet("/", () => Results.Content(RenderAuthPage(), "text/html; charset=utf-8"));

    app.MapGet("/audit", () =>
        Results.Content(RenderAuditPage(logStore.GetAll()), "text/html; charset=utf-8"));

    app.MapGet("/api/audit-events", () => Results.Json(logStore.GetAll().Select(e => new
    {
        when = e.When,
        serverName = e.ServerName,
        who = e.Who,
        objectName = e.ObjectName,
        objectPath = e.ObjectPath,
        operation = e.Operation,
        processName = e.ProcessName,
        from = e.From,
        what = e.What
    })));

    app.MapPost("/api/authenticate", (NasuniAuthRequest request, SyslogListenerService listener) =>
    {
        var errors = new Dictionary<string, string>();

        try
        {
            var options = new IngestionOptions
            {
                NmcHostname = request.NmcHostname,
                NmcUsername = request.NmcUsername,
                NmcPassword = request.NmcPassword,
                EdgeHostname = request.EdgeHostname,
                EdgePort = request.EdgePort == 0 ? 443 : request.EdgePort
            };

            options.ValidateAuthentication();
            listener.Start();
            listener.AddSampleData();
        }
        catch (InvalidOperationException ex)
        {
            var parts = ex.Message.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            foreach (var part in parts)
            {
                if (part.Contains("NmcHostname")) errors[nameof(NasuniAuthRequest.NmcHostname)] = part;
                else if (part.Contains("NmcUsername")) errors[nameof(NasuniAuthRequest.NmcUsername)] = part;
                else if (part.Contains("NmcPassword")) errors[nameof(NasuniAuthRequest.NmcPassword)] = part;
                else if (part.Contains("EdgeHostname")) errors[nameof(NasuniAuthRequest.EdgeHostname)] = part;
                else if (part.Contains("EdgePort")) errors[nameof(NasuniAuthRequest.EdgePort)] = part;
            }

            return Results.Json(new { success = false, errors }, statusCode: StatusCodes.Status400BadRequest);
        }

        return Results.Json(new
        {
            success = true,
            message = "Authentication request accepted.",
            redirect = "/audit"
        });
    });

    app.Run();
}

static string RenderAuditPage(IReadOnlyList<AuditLogEntry> events)
{
    static string DisplayValue(string? value) => string.IsNullOrWhiteSpace(value) ? "N/A" : value;
    static string DisplayDate(DateTimeOffset value) => value == default ? "N/A" : value.ToLocalTime().ToString("MMM dd, yyyy HH:mm:ss");

    var rows = events.Count == 0
        ? "<div class=\"empty-state\"><div class=\"empty-icon\">🗄️</div><div class=\"empty-text\">Please click on the Generate Report button to view data.</div></div>"
        : string.Join(Environment.NewLine, events.Select(e =>
        {
            var when = DisplayDate(e.When);
            var serverName = DisplayValue(e.ServerName);
            var who = DisplayValue(e.Who);
            var objectName = DisplayValue(Path.GetFileName(e.ObjectPath));
            var objectPath = DisplayValue(e.ObjectPath);
            var operation = DisplayValue(e.Operation);
            var processName = DisplayValue(e.ProcessName);
            var from = DisplayValue(e.From);
            var what = DisplayValue(e.What);

            return $"<tr><td>{System.Net.WebUtility.HtmlEncode(when)}</td><td>{System.Net.WebUtility.HtmlEncode(serverName)}</td><td>{System.Net.WebUtility.HtmlEncode(who)}</td><td>{System.Net.WebUtility.HtmlEncode(objectName)}</td><td>{System.Net.WebUtility.HtmlEncode(objectPath)}</td><td>{System.Net.WebUtility.HtmlEncode(operation)}</td><td>{System.Net.WebUtility.HtmlEncode(processName)}</td><td>{System.Net.WebUtility.HtmlEncode(from)}</td><td>{System.Net.WebUtility.HtmlEncode(what)}</td></tr>";
        }));

    var template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Nasuni Audit Log</title>
  <style>
    :root {
      --bg: #f2f5fa;
      --panel: #ffffff;
      --line: #dfe7f4;
      --text: #1f2937;
      --muted: #667085;
      --primary: #2f6fed;
      --primary-dark: #1d4ed8;
    }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--text); }
    .topbar { display: flex; justify-content: space-between; align-items: center; padding: 14px 18px; background: #fff; border-bottom: 1px solid var(--line); }
    .nav { display: flex; gap: 18px; align-items: center; color: var(--muted); font-size: 14px; }
    .toolbar { display: flex; align-items: center; gap: 10px; }
    .iconbtn { border: 1px solid var(--line); background: #fff; border-radius: 8px; padding: 8px 10px; cursor: pointer; }
    .primary-btn { background: var(--primary); color: white; border: none; border-radius: 8px; padding: 10px 18px; font-weight: 700; cursor: pointer; }
    .primary-btn:hover { background: var(--primary-dark); }
    .grid { display: grid; grid-template-columns: repeat(9, minmax(120px, 1fr)); border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); background: #f9fbff; min-height: 68px; }
    .header-cell { padding: 14px 10px; font-size: 13px; color: #4b5b75; font-weight: 700; border-right: 1px solid var(--line); display: flex; align-items: center; gap: 8px; }
    .header-cell:last-child { border-right: 0; }
    .table-wrap { background: var(--panel); min-height: 70vh; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 14px 10px; border-right: 1px solid var(--line); border-bottom: 1px solid var(--line); font-size: 13px; color: #344054; vertical-align: top; }
    th { background: #f8fafc; font-weight: 700; }
    td { background: #fff; }
    .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; padding-top: 200px; color: var(--primary); font-size: 16px; }
    .empty-icon { font-size: 56px; margin-bottom: 18px; color: #4e8cf5; }
    .empty-text { color: #3b5a8d; }
  </style>
</head>
<body>
  <div class="topbar">
    <div class="nav">
      <span>Home</span>
      <span>•</span>
      <span>Reports</span>
      <span>•</span>
      <span>File Server</span>
      <span>•</span>
      <span>Files Copied</span>
    </div>
    <div class="toolbar">
      <button class="iconbtn" type="button">⤴</button>
      <button class="iconbtn" type="button">⌁</button>
      <button class="primary-btn" type="button">Generate Report</button>
    </div>
  </div>

  <div class="table-wrap">
    <div class="grid">
      <div class="header-cell">When</div>
      <div class="header-cell">Server Name</div>
      <div class="header-cell">Who</div>
      <div class="header-cell">Object Name</div>
      <div class="header-cell">Object Path</div>
      <div class="header-cell">Operation</div>
      <div class="header-cell">Process Name</div>
      <div class="header-cell">From</div>
      <div class="header-cell">What</div>
    </div>
    {ROWS}
  </div>
</body>
</html>
""";

    return template.Replace("{ROWS}", rows);
}

static string RenderAuthPage()
{
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Nasuni Authentication</title>
  <style>
    body {
      margin: 0;
      background: #f3f6fb;
      font-family: Arial, sans-serif;
      color: #1f2937;
    }
    .page {
      max-width: 760px;
      margin: 48px auto;
      padding: 24px;
    }
    h1 {
      font-size: 2rem;
      margin-bottom: 24px;
      color: #0f172a;
    }
    .panel {
      background: white;
      border: 1px solid #dfe7f4;
      border-radius: 12px;
      box-shadow: 0 10px 30px rgba(15, 23, 42, 0.04);
      padding: 22px 24px;
      margin-bottom: 20px;
    }
    .panel h2 {
      margin: 0 0 16px;
      font-size: 1.3rem;
      color: #0f172a;
    }
    .field {
      margin-bottom: 16px;
    }
    .field label {
      display: block;
      margin-bottom: 8px;
      font-weight: 600;
      color: #334155;
    }
    .input-wrap {
      position: relative;
    }
    input {
      width: 100%;
      box-sizing: border-box;
      padding: 12px 14px;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      font-size: 1rem;
      background: #fff;
    }
    input:focus {
      outline: 3px solid rgba(59,130,246,0.18);
      border-color: #3b82f6;
    }
    input.invalid {
      border-color: #dc2626;
      background: #fff7f7;
    }
    .password-toggle {
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
      border: 0;
      background: transparent;
      color: #4b5563;
      cursor: pointer;
      font-size: 0.9rem;
    }
    .actions {
      display: flex;
      gap: 12px;
      justify-content: flex-start;
      margin-top: 18px;
    }
    button {
      appearance: none;
      border: none;
      border-radius: 8px;
      padding: 12px 18px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
    }
    .primary {
      background: #2563eb;
      color: white;
    }
    .primary:disabled {
      background: #93c5fd;
      cursor: not-allowed;
    }
    .secondary {
      background: #e2e8f0;
      color: #0f172a;
    }
    .error {
      color: #b91c1c;
      font-size: 0.85rem;
      margin-top: 6px;
      min-height: 18px;
    }
    .success {
      color: #166534;
      font-size: 0.9rem;
      margin-top: 12px;
      display: none;
    }
    .success.visible {
      display: block;
    }
  </style>
</head>
<body>
  <div class="page">
    <h1>Nasuni Authentication</h1>

    <form id="authForm" novalidate>
      <section class="panel">
        <h2>Nasuni Management Console (NMC)</h2>

        <div class="field">
          <label for="nmcHostname">NMC IP or Hostname</label>
          <input id="nmcHostname" name="NmcHostname" type="text" placeholder="192.168.1.10 or nmc.company.com" />
          <div class="error" data-error-for="NmcHostname"></div>
        </div>

        <div class="field">
          <label for="nmcUsername">NMC Username</label>
          <input id="nmcUsername" name="NmcUsername" type="text" placeholder="nasuni-admin" />
          <div class="error" data-error-for="NmcUsername"></div>
        </div>

        <div class="field">
          <label for="nmcPassword">NMC Password</label>
          <div class="input-wrap">
            <input id="nmcPassword" name="NmcPassword" type="password" placeholder="********" />
            <button type="button" class="password-toggle" id="togglePassword" aria-label="Show password">Show</button>
          </div>
          <div class="error" data-error-for="NmcPassword"></div>
        </div>
      </section>

      <section class="panel">
        <h2>Nasuni Edge Appliance (NEA)</h2>

        <div class="field">
          <label for="edgeHostname">Edge Appliance IP or Hostname</label>
          <input id="edgeHostname" name="EdgeHostname" type="text" placeholder="192.168.1.20 or nea.company.com" />
          <div class="error" data-error-for="EdgeHostname"></div>
        </div>

        <div class="field">
          <label for="edgePort">Port Number</label>
          <input id="edgePort" name="EdgePort" type="number" min="1" max="65535" value="443" />
          <div class="error" data-error-for="EdgePort"></div>
        </div>
      </section>

      <div class="actions">
        <button class="primary" id="submitButton" type="submit" disabled>Connect</button>
        <button class="secondary" type="button" id="cancelButton">Cancel</button>
      </div>

      <div id="successMessage" class="success">Authentication request accepted.</div>
    </form>
  </div>

  <script>
    const form = document.getElementById('authForm');
    const submitButton = document.getElementById('submitButton');
    const passwordInput = document.getElementById('nmcPassword');
    const togglePassword = document.getElementById('togglePassword');
    const successMessage = document.getElementById('successMessage');

    function validateField(name, value, rules) {
      const trimmed = String(value || '').trim();
      if (name === 'NmcHostname' || name === 'EdgeHostname') {
        if (!trimmed) return 'This field is required.';
        const validHostPattern = /^(?=.{1,253}$)(?:[a-zA-Z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\])$/;
        if (!validHostPattern.test(trimmed) && !/^localhost$/i.test(trimmed)) return 'Enter a valid IP address or hostname.';
      }
      if (name === 'NmcUsername' || name === 'NmcPassword') {
        if (!trimmed) return 'This field is required.';
      }
      if (name === 'EdgePort') {
        const port = Number(value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) return 'Port must be between 1 and 65535.';
      }
      return '';
    }

    function updateFieldState(name, value) {
      const input = document.getElementsByName(name)[0];
      const errorNode = document.querySelector('[data-error-for="' + name + '"]');
      const message = validateField(name, value, {});
      if (input) input.classList.toggle('invalid', Boolean(message));
      if (errorNode) errorNode.textContent = message;
      return !message;
    }

    function updateFormState() {
      const fields = ['NmcHostname', 'NmcUsername', 'NmcPassword', 'EdgeHostname', 'EdgePort'];
      const anyInvalid = fields.some(name => !updateFieldState(name, document.getElementsByName(name)[0]?.value ?? ''));
      submitButton.disabled = anyInvalid;
    }

    const inputs = form.querySelectorAll('input');
    inputs.forEach((input) => {
      input.addEventListener('input', updateFormState);
      input.addEventListener('blur', updateFormState);
    });

    togglePassword.addEventListener('click', () => {
      const isPassword = passwordInput.type === 'password';
      passwordInput.type = isPassword ? 'text' : 'password';
      togglePassword.textContent = isPassword ? 'Hide' : 'Show';
    });

    document.getElementById('cancelButton').addEventListener('click', () => {
      form.reset();
      document.getElementById('edgePort').value = '443';
      successMessage.classList.remove('visible');
      updateFormState();
    });

    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (submitButton.disabled) return;

      const payload = {
        NmcHostname: document.getElementById('nmcHostname').value,
        NmcUsername: document.getElementById('nmcUsername').value,
        NmcPassword: document.getElementById('nmcPassword').value,
        EdgeHostname: document.getElementById('edgeHostname').value,
        EdgePort: Number(document.getElementById('edgePort').value || '443')
      };

      const response = await fetch('/api/authenticate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        const errorMap = body.errors || {};
        Object.keys(errorMap).forEach((key) => {
          const input = document.getElementsByName(key)[0];
          const note = document.querySelector('[data-error-for="' + key + '"]');
          if (input) input.classList.add('invalid');
          if (note) note.textContent = Array.isArray(errorMap[key]) ? errorMap[key][0] : errorMap[key];
        });
        return;
      }

      Object.keys({ NmcHostname: true, NmcUsername: true, NmcPassword: true, EdgeHostname: true, EdgePort: true }).forEach((key) => {
        const note = document.querySelector('[data-error-for="' + key + '"]');
        if (note) note.textContent = '';
      });
      successMessage.classList.add('visible');
      successMessage.textContent = body.message || 'Authentication request accepted.';
      if (body.redirect) {
        setTimeout(() => {
          window.location.href = body.redirect;
        }, 250);
      }
    });

    updateFormState();
  </script>
</body>
</html>
""";
}

