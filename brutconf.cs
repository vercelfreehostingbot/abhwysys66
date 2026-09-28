// language: C#, file: BruteConfig.cs
namespace Iva.Bot;

public sealed class BruteConfig
{
    public string TargetPan { get; set; } = "";
    public string ExpireMonth { get; set; } = "";
    public string ExpireYear { get; set; } = "";
    public string Pin { get; set; } = "";
    public string TargetMobileNo { get; set; } = "09120000000";
    public long TestAmount { get; set; } = 1000;
    public string ProviderId { get; set; } = "1";

    public int DelayMinMs { get; set; } = 2000;
    public int DelayMaxMs { get; set; } = 5000;
    public int MaxConsecutiveErrors { get; set; } = 3;
    public int MaxTotalAttempts { get; set; } = 1000;

    public string SessionsDir { get; set; } = "./sessions";
    public string LogPath { get; set; } = "./brute.log";

    public BruteConfig Clone() => (BruteConfig)MemberwiseClone();
}