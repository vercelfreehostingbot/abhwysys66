// language: C#, file: ProxyPool.cs
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Iva.Bot;

public sealed class ProxyPool
{
    private readonly ConcurrentDictionary<string, ValidatedProxy> _alive = new();
    private readonly object _lock = new();

    public int Count => _alive.Count;

    public void AddOrUpdate(IEnumerable<ValidatedProxy> proxies)
    {
        lock (_lock)
            foreach (var p in proxies)
                _alive[$"{p.Host}:{p.Port}"] = p;
    }

    public ValidatedProxy? Next()
    {
        var list = _alive.Values.ToArray();
        if (list.Length == 0) return null;
        return list[RandomNumberGenerator.GetInt32(list.Length)];
    }

    public void MarkDead(ValidatedProxy proxy) => _alive.TryRemove($"{proxy.Host}:{proxy.Port}", out _);
    public void MarkAlive(ValidatedProxy proxy) => _alive[$"{proxy.Host}:{proxy.Port}"] = proxy;

    public void SaveToFile(string path) =>
        File.WriteAllLines(path, _alive.Values.Select(p => p.ToLine()));

    public void LoadFromFile(string path)
    {
        if (!File.Exists(path)) return;
        var list = new List<ValidatedProxy>();
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#")) continue;
            var parts = line.Split(':');
            if (parts.Length < 2) continue;
            list.Add(new ValidatedProxy
            {
                Host = parts[0],
                Port = int.Parse(parts[1]),
                User = parts.Length > 2 ? parts[2] : null,
                Pass = parts.Length > 3 ? parts[3] : null,
                Protocol = "http",
            });
        }
        AddOrUpdate(list);
    }
}