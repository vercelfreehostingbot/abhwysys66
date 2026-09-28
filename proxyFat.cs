// language: C#, file: ProxyFetcher.cs
using System.Net.Http;
using System.Text.RegularExpressions;

namespace Iva.Bot;

public sealed class FetchedProxy
{
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string? User { get; set; }
    public string? Pass { get; set; }
    public string? Protocol { get; set; }

    public string ToLine() =>
        string.IsNullOrEmpty(User) ? $"{Host}:{Port}" : $"{Host}:{Port}:{User}:{Pass}";
}

public sealed class ProxyFetcher
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(20) };

    private static readonly string[] Sources =
    {
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=elite",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://www.proxy-list.download/api/v1/get?type=socks4",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
    };

    private static readonly Regex ProxyRegex = new(
        @"^(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?<port>\d{2,5})$",
        RegexOptions.Compiled);

    public async Task<List<FetchedProxy>> FetchAllAsync(CancellationToken ct = default)
    {
        var seen = new HashSet<string>();
        var results = new List<FetchedProxy>();

        var tasks = Sources.Select(async src =>
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, src);
                req.Headers.Add("User-Agent", "Mozilla/5.0");
                using var res = await Http.SendAsync(req, ct);
                if (!res.IsSuccessStatusCode) return Array.Empty<FetchedProxy>();
                var text = await res.Content.ReadAsStringAsync(ct);
                return Parse(text, src);
            }
            catch { return Array.Empty<FetchedProxy>(); }
        });

        var all = await Task.WhenAll(tasks);

        foreach (var batch in all)
            foreach (var p in batch)
                if (seen.Add($"{p.Host}:{p.Port}"))
                    results.Add(p);

        return results;
    }

    private static FetchedProxy[] Parse(string text, string source)
    {
        var protocol = source.Contains("socks5") ? "socks5"
                     : source.Contains("socks4") ? "socks4"
                     : "http";

        var list = new List<FetchedProxy>();
        foreach (var raw in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("#")) continue;
            var m = ProxyRegex.Match(line);
            if (!m.Success) continue;

            list.Add(new FetchedProxy
            {
                Host = m.Groups["ip"].Value,
                Port = int.Parse(m.Groups["port"].Value),
                Protocol = protocol,
            });
        }
        return list.ToArray();
    }
}