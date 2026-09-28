// language: C#, file: ProxyRefresher.cs
namespace Iva.Bot;

public sealed class ProxyRefresher
{
    private readonly ProxyFetcher _fetcher;
    private readonly ProxyValidator _validator;
    private readonly TimeSpan _interval;
    private readonly Action<List<ValidatedProxy>> _onRefresh;

    public ProxyRefresher(
        ProxyFetcher fetcher,
        ProxyValidator validator,
        TimeSpan interval,
        Action<List<ValidatedProxy>> onRefresh)
    {
        _fetcher = fetcher;
        _validator = validator;
        _interval = interval;
        _onRefresh = onRefresh;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var fetched = await _fetcher.FetchAllAsync(ct);
                var valid = await _validator.ValidateAllAsync(fetched, ct);
                if (valid.Count > 0) _onRefresh(valid);
            }
            catch { }

            try { await Task.Delay(_interval, ct); }
            catch (OperationCanceledException) { break; }
        }
    }
}