using System.Collections.Concurrent;

namespace NasuniAuditIngest.Listening;

public sealed class AuditLogStore
{
    private readonly ConcurrentQueue<AuditLogEntry> _events = new();

    public void Add(AuditLogEntry entry) => _events.Enqueue(entry);

    public IReadOnlyList<AuditLogEntry> GetAll() => _events.ToArray();

    public void Clear()
    {
        while (_events.TryDequeue(out _))
        {
        }
    }
}
