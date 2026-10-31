using NasuniAuditIngest.Configuration;
using NasuniAuditIngest.Parsing;
using Xunit;

namespace NasuniAuditIngest.Tests;

public sealed class NasuniAuditParserTests
{
    private static NasuniAuditParser CreateParser() => new(new IngestionOptions
    {
        TenantId = "tenant-test",
        SourceId = "nasuni-test-01",
        SourceInstance = "edge-test",
        ParserVersion = "test"
    });

    [Fact]
    public void ParsesDocumentedJsonShape()
    {
        const string json = """
        {"event_type":"AUDIT_READ","sequence":23,"timestamp":1617656899.135072,
         "username":"sample-user","proto":"AUDIT_PROTO_CIFS","ipaddr":"10.1.2.3",
         "volume":"volume-guid","path":"/example.txt","result":0}
        """;
        var evt = CreateParser().Parse(json, "jsonl");
        Assert.Equal("nasuni", evt.SourceType);
        Assert.Equal("AUDIT_READ", evt.EventType);
        Assert.Equal("sample-user", evt.ActorId);
        Assert.Equal("/example.txt", evt.TargetPath);
        Assert.Equal(23UL, evt.SourceSequence);
        Assert.NotNull(evt.SourceEventKey);
        Assert.Equal("unknown", evt.Outcome);
    }

    [Fact]
    public void ParsesDocumentedThirteenColumnCsvShape()
    {
        const string csv = "2023-09-19 22:48:39.697221,Read,Read Directory,/.snapshot,,DOMAIN\\\\user,domain users,S-1-5-21-1,files,CIFS,10.10.10.10,,";
        var evt = CreateParser().Parse(csv, "csv");
        Assert.Equal("nasuni", evt.SourceType);
        Assert.Equal("nasuni.audit.read.directory", evt.EventType);
        Assert.Equal("DOMAIN\\\\user", evt.ActorId);
        Assert.Equal("/.snapshot", evt.TargetPath);
        Assert.Null(evt.SourceEventKey);
    }

    [Fact]
    public void RejectsUnsupportedFormat() =>
        Assert.Throws<FormatException>(() => CreateParser().Parse("anything", "syslog"));

    [Fact]
    public void RejectsOversizedRecord()
    {
        var parser = new NasuniAuditParser(new IngestionOptions
        {
            TenantId = "t", SourceId = "s", SourceInstance = "i", MaxRecordBytes = 5
        });
        Assert.Throws<FormatException>(() => parser.Parse("123456", "csv"));
    }

    [Fact]
    public void ValidatesNasuniAuthenticationSettings()
    {
        var valid = new IngestionOptions
        {
            NmcHostname = "nmc.company.com",
            NmcUsername = "nasuni-admin",
            NmcPassword = "P@ssw0rd!",
            EdgeHostname = "nea.company.com",
            EdgePort = 443
        };

        var ex = Record.Exception(() => valid.ValidateAuthentication());
        Assert.Null(ex);
    }

    [Fact]
    public void RejectsInvalidNasuniAuthenticationSettings()
    {
        var invalid = new IngestionOptions
        {
            NmcHostname = "",
            NmcUsername = " ",
            NmcPassword = "",
            EdgeHostname = "bad host!",
            EdgePort = 70000
        };

        var ex = Assert.Throws<InvalidOperationException>(() => invalid.ValidateAuthentication());
        Assert.Contains("NmcHostname", ex.Message);
        Assert.Contains("NmcUsername", ex.Message);
        Assert.Contains("NmcPassword", ex.Message);
        Assert.Contains("EdgeHostname", ex.Message);
        Assert.Contains("EdgePort", ex.Message);
    }

    [Fact]
    public void ParsesSyslogAuditLine()
    {
        var line = "<34>Oct 28 10:15:45 nasuni-edge-01 user=alice op=READ path=/data/files/report.pdf src=10.10.9.12 proc=nasuni-filer";

        var parsed = NasuniAuditIngest.Listening.SyslogEventParser.Parse(line);

        Assert.Equal("alice", parsed.Who);
        Assert.Equal("READ", parsed.Operation);
        Assert.Equal("/data/files/report.pdf", parsed.ObjectPath);
        Assert.Equal("10.10.9.12", parsed.From);
        Assert.Equal("nasuni-edge-01", parsed.ServerName);
        Assert.Equal("nasuni-filer", parsed.ProcessName);
    }

    [Fact]
    public void LoadsSampleJsonlAuditEventsFromDisk()
    {
        var entries = NasuniAuditIngest.Listening.SyslogListenerService.LoadSampleEntries();

        Assert.NotEmpty(entries);
        Assert.Equal("sample-user", entries[0].Who);
        Assert.Equal("AUDIT_READDIR", entries[0].Operation);
        Assert.Equal("/", entries[0].ObjectPath);
        Assert.Equal("192.0.2.25", entries[0].From);
    }

    [Fact]
    public void FallsBackToGenericParserForUnknownVendorLogs()
    {
        const string json = """
        {"component":"EMC","timestamp":1700000000,"event_type":"READ","username":"emc-admin","path":"/storage/test","ipaddr":"10.10.10.21","result":0}
        """;

        var evt = CreateParser().Parse(json, "jsonl");

        Assert.Equal("EMC", evt.SourceType);
        Assert.Equal("READ", evt.EventType);
        Assert.Equal("emc-admin", evt.ActorId);
        Assert.Equal("/storage/test", evt.TargetPath);
        Assert.Equal("10.10.10.21", evt.ClientIp);
    }
}
