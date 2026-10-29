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
}
