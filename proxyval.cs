// language: C#, file: ProxyValidator.cs
using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

namespace Iva.Bot;

public sealed class ValidatedProxy
{
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string? User { get; set; }
    public string? Pass { get; set; }
    public string Protocol { get; set; } = "http";
    public long LatencyMs { get; set; }

    public string ToLine() =>
        string.IsNullOrEmpty(User) ? $"{Host}:{Port}" : $"{Host}:{Port}:{User}:{Pass}";
}

public sealed class ProxyValidator
{
    private readonly int _parallelism;
    private readonly int _timeoutMs;

    public ProxyValidator(int parallelism = 150, int timeoutMs = 8000)
    {
        _parallelism = parallelism;
        _timeoutMs = timeoutMs;
    }

    public async Task<List<ValidatedProxy>> ValidateAllAsync(
        List<FetchedProxy> candidates, CancellationToken ct = default)
    {
        var valid = new List<ValidatedProxy>();
        var semaphore = new SemaphoreSlim(_parallelism);
        var tasks = new List<Task>();

        foreach (var c in candidates)
        {
            await semaphore.WaitAsync(ct);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var v = await ValidateAsync(c, ct);
                    if (v is not null) lock (valid) valid.Add(v);
                }
                finally { semaphore.Release(); }
            }, ct));
        }

        await Task.WhenAll(tasks);
        return valid.OrderBy(p => p.LatencyMs).ToList();
    }

    private async Task<ValidatedProxy?> ValidateAsync(FetchedProxy c, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var proxy = new WebProxy(c.Host, c.Port);
            if (!string.IsNullOrEmpty(c.User))
                proxy.Credentials = new NetworkCredential(c.User, c.Pass);

            var handler = new HttpClientHandler
            {
                Proxy = proxy,
                UseProxy = true,
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            };

            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(_timeoutMs) };
            using var res = await client.GetAsync("http://httpbin.org/ip", ct);
            if (!res.IsSuccessStatusCode) return null;

            var text = await res.Content.ReadAsStringAsync(ct);
            var match = Regex.Match(text, @"""origin""\s*:\s*""([^""]+)""");
            var externalIp = match.Success ? match.Groups[1].Value : null;

            if (externalIp is not null && externalIp.Contains(c.Host)) return null;

            sw.Stop();
            return new ValidatedProxy
            {
                Host = c.Host,
                Port = c.Port,
                User = c.User,
                Pass = c.Pass,
                Protocol = c.Protocol ?? "http",
                LatencyMs = sw.ElapsedMilliseconds,
            };
        }
        catch { return null; }
    }
}