using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Iva.Auth
{
    public static class IvaConstants
    {
        public const string ApiBaseUrl = "https://ivaapi.sadadpsp.ir";
        public const string ApiPrefix = "/pwa/api";
        public const string PublicKeyUrl = "https://tsm.shaparak.ir/mobileApp/getKey";
        public const string AppVersion = "3.10.24";

        public static class Endpoints
        {
            public const string KeyExchange = "/v1/users/auth/keyExchange";
            public const string RegisterRequest = "/v1/users/auth/verifyCode";
            public const string Activation = "/v1/users/auth/token";
            public const string RefreshToken = "/v1/users/auth/refreshtoken";
            public const string UserProfile = "/v1/users/me";
            public const string AppConfiguration = "/v1/baseInfo/configs/list";
            public const string ChargeCatalog = "/v3/charges/pin/mobile/catalog";
            public const string PayCharge = "/v1/charges/pin/payment";
            public const string TopupRequest = "/v1/charges/topup/payment";
        }

        public static readonly IReadOnlySet<string> SignExclude = new HashSet<string>
        {
            Endpoints.KeyExchange,
            Endpoints.RegisterRequest,
            Endpoints.Activation,
            Endpoints.RefreshToken,
        };

        public static class StorageKeys
        {
            public const string Token = "token";
            public const string RefreshToken = "refreshToken";
            public const string AccessTokenExpTime = "accessTokenExpTime";
            public const string TokenType = "tokenType";
            public const string AccessTokenObtainedAt = "accessTokenObtainedAt";
            public const string SharedKey = "shared_key";
            public const string WorkingKey = "working_key";
            public const string RsaPublic = "rsaPublic";
            public const string PichakRsaPublic = "pichakRSAPublic";
        }

        public static readonly byte[] DefaultAesIv = new byte[16];
        public static readonly byte[] CustomAesIv = new byte[]
        {
            48, 148, 136, 186, 72, 57, 83, 116, 19, 138, 210, 230, 3, 165, 240, 35
        };
    }

    public class IvaOptions
    {
        public string ApiBaseUrl { get; set; } = IvaConstants.ApiBaseUrl;
        public string ApiPrefix { get; set; } = IvaConstants.ApiPrefix;
        public string PublicKeyUrl { get; set; } = IvaConstants.PublicKeyUrl;
        public string? KeyId { get; set; }
        public string? TransactionId { get; set; }
        public string AppVersion { get; set; } = IvaConstants.AppVersion;
        public TimeSpan Timeout { get; set; } = TimeSpan.FromMilliseconds(65000);
        public int MaxChargeRetries { get; set; } = 10;
        public TimeSpan ChargeRetryDelay { get; set; } = TimeSpan.FromMilliseconds(500);
        public string? ChargeProxy { get; set; }

        public List<string> RetryableStatusMessages { get; set; } = new()
        {
            "محدودیت روزانه تراکنش",
            "عملیات ناموفق بود",
            "سرویس در حال حاضر قادر به پاسخگویی نیست",
        };

        public List<string> DailyLimitMessages { get; set; } = new()
        {
            "محدودیت روزانه تراکنش",
        };

        public string BaseAddress => ApiBaseUrl.TrimEnd('/') + ApiPrefix;
    }

    public interface IKeyStore
    {
        string? Get(string key);
        void Set(string key, string value);
        bool Has(string key);
        void Remove(string key);
    }

    public sealed class InMemoryKeyStore : IKeyStore
    {
        private readonly ConcurrentDictionary<string, string> _data = new();

        public string? Get(string key) => _data.TryGetValue(key, out var v) ? v : null;
        public void Set(string key, string value) => _data[key] = value;
        public bool Has(string key) => _data.ContainsKey(key);
        public void Remove(string key) => _data.TryRemove(key, out _);
    }

    public interface ISessionRepository
    {
        IReadOnlyList<string> ListPhones();
        SessionData? Load(string phone);
        void Save(SessionData session);
        void Delete(string phone);
        bool Exists(string phone);
    }

    public class SessionData
    {
        public string? Phone { get; set; }
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
        public string? TokenType { get; set; }
        public long? ExpiresIn { get; set; }
        public long? AccessTokenObtainedAt { get; set; }
        public string? SharedKey { get; set; }
        public string? WorkingKey { get; set; }
        public string? RsaPublic { get; set; }
    }

    public sealed class FileSessionRepository : ISessionRepository
    {
        private readonly string _directory;

        public FileSessionRepository(string? directory = null)
        {
            _directory = directory ?? Path.Combine(AppContext.BaseDirectory, "sessions");
            Directory.CreateDirectory(_directory);
        }

        private string GetPath(string phone) => Path.Combine(_directory, $"{phone}.json");

        public IReadOnlyList<string> ListPhones()
        {
            return Directory.GetFiles(_directory, "*.json")
                .Select(Path.GetFileNameWithoutExtension)
                .Where(x => !string.IsNullOrEmpty(x))
                .Select(x => x!)
                .ToList();
        }

        public SessionData? Load(string phone)
        {
            var path = GetPath(phone);
            if (!File.Exists(path)) return null;
            try
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<SessionData>(json);
            }
            catch
            {
                return null;
            }
        }

        public void Save(SessionData session)
        {
            if (string.IsNullOrEmpty(session.Phone)) return;
            var json = JsonSerializer.Serialize(session, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(GetPath(session.Phone), json);
        }

        public void Delete(string phone)
        {
            var path = GetPath(phone);
            if (File.Exists(path)) File.Delete(path);
        }

        public bool Exists(string phone) => File.Exists(GetPath(phone));
    }

    public sealed class IvaCrypto
    {
        private readonly IKeyStore _store;

        public IvaCrypto(IKeyStore store)
        {
            _store = store;
        }

        public byte[] GenerateKey(int? bytes = null)
        {
            return RandomNumberGenerator.GetBytes(bytes ?? 32);
        }

        public string AesEncrypt(string plaintext, string? keyBase64 = null)
        {
            return AesEncryptWithIv(plaintext, keyBase64, IvaConstants.DefaultAesIv);
        }

        public string AesEncrypt2(string plaintext, string? keyBase64 = null, byte[]? iv = null)
        {
            return AesEncryptWithIv(plaintext, keyBase64, iv ?? IvaConstants.CustomAesIv);
        }

        public string AesDecrypt(string hex, string? keyBase64 = null)
        {
            return AesDecryptWithIv(hex, keyBase64, IvaConstants.DefaultAesIv);
        }

        private byte[] ResolveSharedKey(string? keyBase64)
        {
            var b64 = keyBase64 ?? _store.Get(IvaConstants.StorageKeys.SharedKey)
                ?? throw new InvalidOperationException("Shared key is not set. Run KeyExchange first.");
            return Convert.FromBase64String(b64);
        }

        private string AesEncryptWithIv(string plaintext, string? keyBase64, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = ResolveSharedKey(keyBase64);
            aes.IV = iv;

            var data = Encoding.UTF8.GetBytes(plaintext);
            using var enc = aes.CreateEncryptor();
            var cipher = enc.TransformFinalBlock(data, 0, data.Length);
            return Convert.ToHexString(cipher).ToLowerInvariant();
        }

        private string AesDecryptWithIv(string hex, string? keyBase64, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = ResolveSharedKey(keyBase64);
            aes.IV = iv;

            var data = Convert.FromHexString(hex);
            using var dec = aes.CreateDecryptor();
            var plain = dec.TransformFinalBlock(data, 0, data.Length);
            return Encoding.UTF8.GetString(plain);
        }

        public string Hmac(string data)
        {
            var keyB64 = _store.Get(IvaConstants.StorageKeys.WorkingKey)
                ?? throw new InvalidOperationException("Working key is not set. Run KeyExchange first.");
            var key = Convert.FromBase64String(keyB64);
            using var hmac = new HMACSHA256(key);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            return Convert.ToBase64String(hash);
        }

        public string RsaEncrypt(string plaintext)
        {
            using var rsa = ImportPublicKey(
                _store.Get(IvaConstants.StorageKeys.RsaPublic)
                ?? throw new InvalidOperationException("RSA public key is not set."));
            var cipher = rsa.Encrypt(Encoding.UTF8.GetBytes(plaintext), RSAEncryptionPadding.Pkcs1);
            return Convert.ToHexString(cipher).ToLowerInvariant();
        }

        public string PichakRsaEncrypt(string plaintext, string? publicKey = null)
        {
            var key = publicKey ?? _store.Get(IvaConstants.StorageKeys.PichakRsaPublic)
                ?? throw new InvalidOperationException("Pichak RSA public key is not set.");
            var rsaParams = ToBouncyPublicKey(key);

            var oaep = new OaepEncoding(
                new RsaEngine(),
                new Sha256Digest(),
                new Sha1Digest(),
                null);
            oaep.Init(true, rsaParams);

            var input = Encoding.UTF8.GetBytes(plaintext);
            var output = oaep.ProcessBlock(input, 0, input.Length);
            return Convert.ToBase64String(output);
        }

        public static RSA ImportPublicKey(string key)
        {
            var rsa = RSA.Create();
            var trimmed = key.Trim();

            if (trimmed.Contains("BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(trimmed);
                return rsa;
            }

            var bytes = Convert.FromBase64String(StripBase64(trimmed));

            try
            {
                rsa.ImportSubjectPublicKeyInfo(bytes, out _);
                return rsa;
            }
            catch (CryptographicException)
            {
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = bytes,
                    Exponent = new byte[] { 0x01, 0x00, 0x01 },
                });
                return rsa;
            }
        }

        private static RsaKeyParameters ToBouncyPublicKey(string key)
        {
            var trimmed = key.Trim();

            if (trimmed.Contains("BEGIN", StringComparison.Ordinal))
            {
                var obj = new PemReader(new StringReader(trimmed)).ReadObject();
                return obj switch
                {
                    RsaKeyParameters p => p,
                    AsymmetricKeyParameter ak => (RsaKeyParameters)ak,
                    _ => throw new InvalidOperationException("Unsupported PEM key material."),
                };
            }

            var der = Convert.FromBase64String(StripBase64(trimmed));
            try
            {
                return (RsaKeyParameters)PublicKeyFactory.CreateKey(der);
            }
            catch
            {
                var modulus = new Org.BouncyCastle.Math.BigInteger(1, der);
                var exponent = Org.BouncyCastle.Math.BigInteger.ValueOf(65537);
                return new RsaKeyParameters(false, modulus, exponent);
            }
        }

        private static string StripBase64(string s) =>
            s.Replace("\r", "").Replace("\n", "").Replace(" ", "");

        public static string Base64ToHex(string base64) =>
            Convert.ToHexString(Convert.FromBase64String(base64)).ToLowerInvariant();

        public static string HexToBase64(string hex) =>
            Convert.ToBase64String(Convert.FromHexString(hex));

        public static string Base64ModulusToPem(string base64Modulus)
        {
            const string spkiPrefix =
                "30820122300D06092A864886F70D01010105000382010F003082010A0282010100";
            const string spkiSuffix = "0203010001";
            var der = spkiPrefix + Base64ToHex(base64Modulus) + spkiSuffix;
            var b64 = HexToBase64(der);
            var lines = string.Join("\n",
                Enumerable.Range(0, (b64.Length + 63) / 64)
                          .Select(i => b64.Substring(i * 64, Math.Min(64, b64.Length - i * 64))));
            return $"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----";
        }
    }

    public sealed class IvaAuthClient : IDisposable
    {
        private static readonly JsonSerializerOptions Json = new()
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };

        private static readonly JsonSerializerOptions JsonPretty = new()
        {
            WriteIndented = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };

        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly IvaOptions _opts;
        private readonly ISessionRepository? _sessions;
        private HttpClient? _proxyHttp;

        public string? CurrentPhone { get; private set; }
        public IKeyStore Store { get; }
        public IvaCrypto Crypto { get; }

        public event Action<TokenResult>? TokenRefreshed;

        public IvaAuthClient(
            IvaOptions? options = null,
            IKeyStore? store = null,
            HttpClient? http = null,
            ISessionRepository? sessions = null)
        {
            _opts = options ?? new IvaOptions();
            Store = store ?? new InMemoryKeyStore();
            Crypto = new IvaCrypto(Store);
            _sessions = sessions;

            _ownsHttp = http is null;
            _http = http ?? new HttpClient();
            _http.Timeout = _opts.Timeout;
        }

        private HttpClient GetProxyClient()
        {
            if (_proxyHttp is not null) return _proxyHttp;

            var s = _opts.ChargeProxy;
            if (string.IsNullOrWhiteSpace(s))
                throw new InvalidOperationException("ChargeProxy is not configured.");

            var p = s.Split(':');
            if (p.Length < 2 || !int.TryParse(p[1], out var port))
                throw new InvalidOperationException("ChargeProxy must be host:port:username:password.");
            var host = p[0];
            var user = p.Length > 2 ? p[2] : "";
            var pass = p.Length > 3 ? string.Join(":", p.Skip(3)) : "";

            var proxy = new WebProxy(host, port);
            if (!string.IsNullOrEmpty(user))
                proxy.Credentials = new NetworkCredential(user, pass);

            var handler = new HttpClientHandler { Proxy = proxy, UseProxy = true };
            _proxyHttp = new HttpClient(handler) { Timeout = _opts.Timeout };
            return _proxyHttp;
        }

        public async Task<string> FetchPublicKeyAsync(
            string? keyId = null, string? transactionId = null, CancellationToken ct = default)
        {
            var body = new { keyId = keyId ?? _opts.KeyId, transactionId = transactionId ?? _opts.TransactionId };
            var json = JsonSerializer.Serialize(body, Json);

            using var req = new HttpRequestMessage(HttpMethod.Post, _opts.PublicKeyUrl)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };

            using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!res.IsSuccessStatusCode)
                throw new Exception($"getKey failed (HTTP {(int)res.StatusCode}): {text}");

            string? keyData = null;
            try
            {
                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;

                if (root.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0)
                    throw new Exception("getKey returned errors: " + errs.GetRawText());

                keyData = TryGetString(root, "keyData")
                       ?? (root.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Object ? TryGetString(d, "keyData") : null)
                       ?? TryGetString(root, "data");
            }
            catch (JsonException)
            {
            }

            if (string.IsNullOrEmpty(keyData))
                throw new Exception("getKey response did not contain keyData: " + text);

            Store.Set(IvaConstants.StorageKeys.RsaPublic, keyData);
            return keyData;
        }

        public void SetPublicKey(string pemOrBase64) => Store.Set(IvaConstants.StorageKeys.RsaPublic, pemOrBase64);

        public async Task KeyExchangeAsync(CancellationToken ct = default)
        {
            var sharedKey = Crypto.GenerateKey();
            Store.Set(IvaConstants.StorageKeys.SharedKey, Convert.ToBase64String(sharedKey));

            var workingKey = Crypto.GenerateKey();
            Store.Set(IvaConstants.StorageKeys.WorkingKey, Convert.ToBase64String(workingKey));

            var sharedHex = Convert.ToHexString(sharedKey).ToLowerInvariant();
            var workingHex = Convert.ToHexString(workingKey).ToLowerInvariant();

            var dataKey = Crypto.RsaEncrypt(sharedHex);
            var macKey = Crypto.RsaEncrypt(workingHex);

            var sent = new { DataKey = dataKey, MacKey = macKey };
            await PostTolerantAsync(IvaConstants.Endpoints.KeyExchange, sent, ct).ConfigureAwait(false);
        }

        public Task<OtpRequestResult> RequestOtpAsync(string phoneNumber, CancellationToken ct = default)
        {
            CurrentPhone = phoneNumber;
            return PostDataAsync<OtpRequestResult>(IvaConstants.Endpoints.RegisterRequest,
                new { PhoneNumber = phoneNumber }, ct);
        }

        public async Task<TokenResult> VerifyCodeAsync(
            string verificationCode, string? token, string? reagentNumber, CancellationToken ct = default)
        {
            var data = await PostDataAsync<TokenResult>(IvaConstants.Endpoints.Activation, new
            {
                VerificationCode = verificationCode,
                Token = token,
                ReagentNumber = reagentNumber,
            }, ct).ConfigureAwait(false);

            PersistTokens(data);
            SaveSession();
            return data;
        }

        public async Task<TokenResult> RefreshTokenAsync(string? refreshToken = null, CancellationToken ct = default)
        {
            var rt = refreshToken ?? Store.Get(IvaConstants.StorageKeys.RefreshToken)
                ?? throw new InvalidOperationException("No refresh token available.");

            var data = await PostDataAsync<TokenResult>(IvaConstants.Endpoints.RefreshToken,
                new { RefreshToken = rt }, ct).ConfigureAwait(false);

            PersistTokens(data);
            SaveSession();
            TokenRefreshed?.Invoke(data);
            return data;
        }

        public string Bearer() => "Bearer " + Store.Get(IvaConstants.StorageKeys.Token);

        public async Task EnsureSecureChannelAsync(CancellationToken ct = default)
        {
            if (Store.Has(IvaConstants.StorageKeys.SharedKey) && Store.Has(IvaConstants.StorageKeys.WorkingKey))
                return;

            if (!Store.Has(IvaConstants.StorageKeys.RsaPublic))
                await TryDiscoverPublicKeyAsync(ct).ConfigureAwait(false);

            if (!Store.Has(IvaConstants.StorageKeys.RsaPublic))
                throw new InvalidOperationException(
                    "RSA public key could not be found. Provide it via SetPublicKey.");

            await KeyExchangeAsync(ct).ConfigureAwait(false);
            SaveSession();
        }

        public async Task TryDiscoverPublicKeyAsync(CancellationToken ct = default)
        {
            var version = _opts.AppVersion.Split('.');
            var query = new Dictionary<string, string?>
            {
                ["VersionCode"] = version.Length > 2 ? version[2] : _opts.AppVersion,
                ["ClientType"] = "3",
                ["MarketType"] = "4",
            };

            JsonElement config;
            try
            {
                config = await GetDataElementAsync(IvaConstants.Endpoints.AppConfiguration, query, ct).ConfigureAwait(false);
            }
            catch
            {
                return;
            }

            var key = FindPublicKey(config);
            if (!string.IsNullOrEmpty(key))
            {
                Store.Set(IvaConstants.StorageKeys.RsaPublic, key!);
            }
        }

        private static string? FindPublicKey(JsonElement el)
        {
            switch (el.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var prop in el.EnumerateObject())
                    {
                        var name = prop.Name.ToLowerInvariant();
                        if (prop.Value.ValueKind == JsonValueKind.String)
                        {
                            var val = prop.Value.GetString() ?? "";
                            var nameMatch = (name.Contains("public") && name.Contains("key")) ||
                                            name.Contains("rsapublic") || name == "rsapublickey";
                            if (nameMatch && LooksLikeKey(val)) return val;
                        }
                        var nested = FindPublicKey(prop.Value);
                        if (nested is not null) return nested;
                    }
                    break;
                case JsonValueKind.Array:
                    foreach (var item in el.EnumerateArray())
                    {
                        var nested = FindPublicKey(item);
                        if (nested is not null) return nested;
                    }
                    break;
            }
            return null;
        }

        private static bool LooksLikeKey(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return false;
            if (s.Contains("BEGIN", StringComparison.Ordinal)) return true;
            var compact = s.Replace("\r", "").Replace("\n", "").Trim();
            return compact.Length >= 200 &&
                   compact.All(c => char.IsLetterOrDigit(c) || c is '+' or '/' or '=');
        }

        public Task<JsonElement> GetProfileAsync(CancellationToken ct = default) =>
            GetDataElementAsync(IvaConstants.Endpoints.UserProfile, query: null, ct);

        public async Task<IReadOnlyList<ChargeOperator>> GetChargeCatalogAsync(CancellationToken ct = default)
        {
            var data = await GetDataElementAsync(IvaConstants.Endpoints.ChargeCatalog, query: null, ct).ConfigureAwait(false);

            var array = FindFirstArray(data);
            if (array is null) return Array.Empty<ChargeOperator>();

            return array.Value.Deserialize<List<ChargeOperator>>(Json) ?? new List<ChargeOperator>();
        }

        private static JsonElement? FindFirstArray(JsonElement el)
        {
            if (el.ValueKind == JsonValueKind.Array) return el;
            if (el.ValueKind == JsonValueKind.Object)
                foreach (var prop in el.EnumerateObject())
                    if (prop.Value.ValueKind == JsonValueKind.Array)
                        return prop.Value;
            return null;
        }

        internal static bool Contains(IEnumerable<string>? messages, string? serverMessage)
        {
            if (string.IsNullOrEmpty(serverMessage) || messages is null) return false;
            foreach (var m in messages)
                if (!string.IsNullOrEmpty(m) && serverMessage.Contains(m, StringComparison.Ordinal))
                    return true;
            return false;
        }

        public async Task<bool> TryResumeSessionAsync(string phone, CancellationToken ct = default)
        {
            if (!TryResumeSession(phone)) return false;
            try
            {
                await GetProfileAsync(ct).ConfigureAwait(false);
                return true;
            }
            catch
            {
                try
                {
                    await RefreshAuthAsync(ct).ConfigureAwait(false);
                    await GetProfileAsync(ct).ConfigureAwait(false);
                    return true;
                }
                catch { return false; }
            }
        }

        public async Task<ChargePurchaseResult> BuyChargeAsync(
            ChargePurchaseRequest request, CancellationToken ct = default, bool useProxy = false)
        {
            ArgumentNullException.ThrowIfNull(request);
            request.Card.Validate();

            var contentType = PaymentContentType("payment.charge", request.Card);

            await EnsureSecureChannelAsync(ct).ConfigureAwait(false);

            long? orderId = request.OrderId;
            Dictionary<string, object?> BuildBody()
            {
                var extra = new Dictionary<string, object?>
                {
                    ["TTL"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["TargetMobileNo"] = request.TargetMobileNo,
                    ["ProviderId"] = request.ProviderId,
                };
                if (request.Extra is not null)
                    foreach (var kv in request.Extra) extra[kv.Key] = kv.Value;

                var body = CreatePaymentBody(request.Amount, request.Card, extra, pocketId: null, orderId);
                orderId ??= (long)body["OrderId"]!;
                return body;
            }

            var built = BuildBody();
            var (status, text) = await PostSignedOnceAsync(IvaConstants.Endpoints.PayCharge, built, contentType, ct, useProxy)
                .ConfigureAwait(false);

            if (status == HttpStatusCode.Unauthorized)
            {
                await RefreshAuthAsync(ct).ConfigureAwait(false);
                (status, text) = await PostSignedOnceAsync(IvaConstants.Endpoints.PayCharge, BuildBody(), contentType, ct, useProxy)
                    .ConfigureAwait(false);
            }

            return ParseChargeOutcome(text, status);
        }

        private static ChargePurchaseResult ParseChargeOutcome(string text, HttpStatusCode status)
        {
            try
            {
                var env = JsonSerializer.Deserialize<ApiResponse<ChargePurchaseResult>>(text, Json);
                if (env?.Error is { } err && !IsSuccessCode(err.Code))
                    return new ChargePurchaseResult { Success = false, ErrorCode = err.Code, Message = err.Message };

                var data = env?.Data ?? new ChargePurchaseResult();
                data.Success = true;
                return data;
            }
            catch (JsonException)
            {
                return new ChargePurchaseResult { Success = false, ErrorCode = ((int)status).ToString(), Message = $"HTTP {(int)status}" };
            }
        }

        public Dictionary<string, object?> CreatePaymentBody(
            long amount, CardPayment card,
            IReadOnlyDictionary<string, object?>? extra = null,
            string? pocketId = null, long? orderId = null)
        {
            if (!Store.Has(IvaConstants.StorageKeys.SharedKey))
                throw new InvalidOperationException("Secure channel not established. Call EnsureSecureChannelAsync first.");

            var media = new Dictionary<string, object?>();

            if (!string.IsNullOrEmpty(card.Cvv2))
                media["Cvv2"] = Crypto.AesEncrypt(card.Cvv2!);

            if (!string.IsNullOrEmpty(card.Pin))
                media["Pin"] = Crypto.AesEncrypt(card.Pin!);

            var expire = (card.ExpireYear ?? string.Empty) + PadLeft2(card.ExpireMonth);
            if (DigitsOnly(expire).Length == 4)
                media["ExpireDate"] = Crypto.AesEncrypt(expire);

            if (!string.IsNullOrEmpty(card.Token))
                media["Token"] = card.Token;
            else if (!string.IsNullOrEmpty(card.Pan))
                media["Pan"] = Crypto.AesEncrypt(card.Pan!);

            if (!string.IsNullOrEmpty(pocketId))
                media["PocketId"] = pocketId;

            var body = new Dictionary<string, object?> { ["paymentMedia"] = media };
            if (extra is not null)
                foreach (var kv in extra) body[kv.Key] = kv.Value;

            body["Amount"] = amount;
            body["OrderId"] = orderId ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            return body;
        }

        private static string PaymentContentType(string apiHeader, CardPayment card)
        {
            var variant = !string.IsNullOrEmpty(card.Token) ? "Token" : "pan";
            return $"application/vnd.sadad.{apiHeader}.{variant}+json";
        }

        private static string PadLeft2(string? s) =>
            string.IsNullOrEmpty(s) ? string.Empty : (s!.Length >= 2 ? s : s.PadLeft(2, '0'));

        private static string DigitsOnly(string s) =>
            new(s.Where(char.IsDigit).ToArray());

        private void PersistTokens(TokenResult d)
        {
            if (!string.IsNullOrEmpty(d.RefreshToken)) Store.Set(IvaConstants.StorageKeys.RefreshToken, d.RefreshToken!);
            if (!string.IsNullOrEmpty(d.AccessToken)) Store.Set(IvaConstants.StorageKeys.Token, d.AccessToken!);
            if (d.ExpiresIn.HasValue) Store.Set(IvaConstants.StorageKeys.AccessTokenExpTime, d.ExpiresIn.Value.ToString());
            if (!string.IsNullOrEmpty(d.TokenType)) Store.Set(IvaConstants.StorageKeys.TokenType, d.TokenType!);
            Store.Set(IvaConstants.StorageKeys.AccessTokenObtainedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());

            if (!string.IsNullOrEmpty(d.Key))
            {
                try { Store.Set(IvaConstants.StorageKeys.RsaPublic, IvaCrypto.Base64ModulusToPem(d.Key!)); }
                catch { }
            }
        }

        public bool TryResumeSession(string phone)
        {
            if (_sessions is null) return false;
            var s = _sessions.Load(phone);
            if (s is null || string.IsNullOrEmpty(s.Token)) return false;

            CurrentPhone = phone;
            SetOrRemove(IvaConstants.StorageKeys.Token, s.Token);
            SetOrRemove(IvaConstants.StorageKeys.RefreshToken, s.RefreshToken);
            SetOrRemove(IvaConstants.StorageKeys.TokenType, s.TokenType);
            SetOrRemove(IvaConstants.StorageKeys.AccessTokenExpTime, s.ExpiresIn?.ToString());
            SetOrRemove(IvaConstants.StorageKeys.AccessTokenObtainedAt, s.AccessTokenObtainedAt?.ToString());
            SetOrRemove(IvaConstants.StorageKeys.SharedKey, s.SharedKey);
            SetOrRemove(IvaConstants.StorageKeys.WorkingKey, s.WorkingKey);
            SetOrRemove(IvaConstants.StorageKeys.RsaPublic, s.RsaPublic);
            return true;
        }

        public void SaveSession()
        {
            if (_sessions is null || string.IsNullOrEmpty(CurrentPhone)) return;

            _sessions.Save(new SessionData
            {
                Phone = CurrentPhone!,
                Token = Store.Get(IvaConstants.StorageKeys.Token),
                RefreshToken = Store.Get(IvaConstants.StorageKeys.RefreshToken),
                ExpiresIn = ParseLong(Store.Get(IvaConstants.StorageKeys.AccessTokenExpTime)),
                TokenType = Store.Get(IvaConstants.StorageKeys.TokenType),
                AccessTokenObtainedAt = ParseLong(Store.Get(IvaConstants.StorageKeys.AccessTokenObtainedAt)),
                SharedKey = Store.Get(IvaConstants.StorageKeys.SharedKey),
                WorkingKey = Store.Get(IvaConstants.StorageKeys.WorkingKey),
                RsaPublic = Store.Get(IvaConstants.StorageKeys.RsaPublic),
            });
        }

        public bool HasSavedSession(string phone) => _sessions?.Exists(phone) ?? false;

        private void SetOrRemove(string key, string? value)
        {
            if (string.IsNullOrEmpty(value)) Store.Remove(key);
            else Store.Set(key, value);
        }

        private static long? ParseLong(string? s) =>
            long.TryParse(s, out var v) ? v : null;

        public bool IsAccessTokenExpired(int skewSeconds = 30)
        {
            var obtained = ParseLong(Store.Get(IvaConstants.StorageKeys.AccessTokenObtainedAt));
            var expiresIn = ParseLong(Store.Get(IvaConstants.StorageKeys.AccessTokenExpTime));
            if (obtained is null || expiresIn is null) return false;

            var expiresAt = obtained.Value + expiresIn.Value;
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() >= expiresAt - skewSeconds;
        }

        public async Task RefreshAuthAsync(CancellationToken ct = default)
        {
            await RefreshTokenAsync(ct: ct).ConfigureAwait(false);
            if (Store.Has(IvaConstants.StorageKeys.RsaPublic))
                await KeyExchangeAsync(ct).ConfigureAwait(false);
            SaveSession();
        }

        public async Task<HttpResponseMessage> SendAuthorizedAsync(
            Func<HttpRequestMessage> requestFactory, CancellationToken ct = default)
        {
            if (IsAccessTokenExpired())
                await RefreshAuthAsync(ct).ConfigureAwait(false);

            var res = await SendOnceAsync(requestFactory(), ct).ConfigureAwait(false);
            if (res.StatusCode != HttpStatusCode.Unauthorized) return res;

            res.Dispose();
            await RefreshAuthAsync(ct).ConfigureAwait(false);
            return await SendOnceAsync(requestFactory(), ct).ConfigureAwait(false);
        }

        private Task<HttpResponseMessage> SendOnceAsync(HttpRequestMessage req, CancellationToken ct)
        {
            string body = string.Empty;
            if (req.Content is not null)
                body = req.Content.ReadAsStringAsync(ct).GetAwaiter().GetResult();

            ApplyHeaders(req, req.RequestUri?.AbsolutePath ?? string.Empty, body);
            return _http.SendAsync(req, ct);
        }

        private async Task<T> PostDataAsync<T>(string path, object body, CancellationToken ct)
        {
            var envelope = await PostAsync<T>(path, body, ct).ConfigureAwait(false);
            return envelope.Data ?? throw new Exception("Empty response data.");
        }

        private async Task PostTolerantAsync(string path, object body, CancellationToken ct)
        {
            var json = JsonSerializer.Serialize(body, Json);
            using var req = new HttpRequestMessage(HttpMethod.Post, _opts.BaseAddress + path)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            ApplyHeaders(req, path, json);

            using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!res.IsSuccessStatusCode)
                throw new Exception($"{path} failed (HTTP {(int)res.StatusCode}).");

            if (!string.IsNullOrWhiteSpace(text))
            {
                try
                {
                    var env = JsonSerializer.Deserialize<ApiResponse<JsonElement>>(text, Json);
                    if (env?.Error is { } err && !IsSuccessCode(err.Code))
                        throw new Exception(err.Message ?? "Operation failed.");
                }
                catch (JsonException) { }
            }
        }

        private async Task<ApiResponse<T>> PostAsync<T>(string path, object body, CancellationToken ct)
        {
            var json = JsonSerializer.Serialize(body, Json);

            using var req = new HttpRequestMessage(HttpMethod.Post, _opts.BaseAddress + path)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
            ApplyHeaders(req, path, json);

            using var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            ApiResponse<T>? parsed;
            try
            {
                parsed = JsonSerializer.Deserialize<ApiResponse<T>>(text, Json);
            }
            catch (JsonException)
            {
                throw new Exception($"Unexpected response (HTTP {(int)res.StatusCode}).");
            }

            parsed ??= new ApiResponse<T>();

            if (parsed.Error is { } err && !IsSuccessCode(err.Code))
                throw new Exception(err.Message ?? "Operation failed.");

            return parsed;
        }

        private async Task<JsonElement> GetDataElementAsync(
            string path, IReadOnlyDictionary<string, string?>? query, CancellationToken ct)
        {
            var url = _opts.BaseAddress + path + BuildQuery(query);
            using var res = await SendAuthorizedAsync(
                () => new HttpRequestMessage(HttpMethod.Get, url), ct).ConfigureAwait(false);

            var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            ThrowIfErrorEnvelope(root, res.StatusCode);
            return root.TryGetProperty("data", out var data) ? data.Clone() : root.Clone();
        }

        private static void ThrowIfErrorEnvelope(JsonElement root, HttpStatusCode status)
        {
            if (root.ValueKind != JsonValueKind.Object) return;
            if (!root.TryGetProperty("error", out var err) || err.ValueKind != JsonValueKind.Object) return;
            if (!err.TryGetProperty("code", out var code)) return;

            var codeStr = code.ValueKind == JsonValueKind.Number ? code.GetRawText() : code.GetString();
            if (codeStr is null || codeStr == "200") return;

            var message = err.TryGetProperty("message", out var m) ? m.GetString() : null;
            throw new Exception(message ?? "Operation failed.");
        }

        private async Task<(HttpStatusCode Status, string Text)> PostSignedOnceAsync(
            string path, object body, string contentType, CancellationToken ct, bool useProxy = false)
        {
            var json = JsonSerializer.Serialize(body, Json);

            using var content = new StringContent(json, Encoding.UTF8);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(contentType);

            using var req = new HttpRequestMessage(HttpMethod.Post, _opts.BaseAddress + path) { Content = content };
            ApplyHeaders(req, path, json);

            var http = useProxy ? GetProxyClient() : _http;
            using var res = await http.SendAsync(req, ct).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return (res.StatusCode, text);
        }

        private static string BuildQuery(IReadOnlyDictionary<string, string?>? query)
        {
            if (query is null || query.Count == 0) return string.Empty;
            var parts = query.Where(kv => kv.Value is not null)
                             .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}");
            var joined = string.Join("&", parts);
            return joined.Length == 0 ? string.Empty : "?" + joined;
        }

        private void ApplyHeaders(HttpRequestMessage req, string path, string serializedBody)
        {
            if (Store.Has(IvaConstants.StorageKeys.Token))
            {
                req.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Store.Get(IvaConstants.StorageKeys.Token));
                req.Headers.TryAddWithoutValidation("iva-versioncode", _opts.AppVersion.Replace(".", ""));
                req.Headers.TryAddWithoutValidation("iva-versionname", _opts.AppVersion);
            }

            if (!string.IsNullOrEmpty(serializedBody) && !IvaConstants.SignExclude.Contains(path))
            {
                req.Headers.TryAddWithoutValidation("Sign-Data", Crypto.Hmac(serializedBody));
            }
        }

        private static bool IsSuccessCode(string? code) =>
            code is null || code == "200";

        private static string? TryGetString(JsonElement el, string name) =>
            el.ValueKind == JsonValueKind.Object && el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;

        public void Dispose()
        {
            if (_ownsHttp) _http.Dispose();
            _proxyHttp?.Dispose();
        }
    }

    public sealed record TokenResult
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public string? TokenType { get; set; }
        public long? ExpiresIn { get; set; }
        public string? Key { get; set; }
    }

    public sealed record OtpRequestResult
    {
        public string? Token { get; set; }
        public string? ReagentNumber { get; set; }
    }

    public sealed record ApiResponse<T>
    {
        public T? Data { get; set; }
        public ApiError? Error { get; set; }
    }

    public sealed record ApiError
    {
        public string? Code { get; set; }
        public string? Message { get; set; }
    }

    public sealed class ChargePurchaseRequest
    {
        public long Amount { get; set; }
        public string? TargetMobileNo { get; set; }
        public string? ProviderId { get; set; }
        public CardPayment Card { get; set; } = new();
        public long? OrderId { get; set; }
        public Dictionary<string, object?>? Extra { get; set; }
    }

    public sealed class CardPayment
    {
        public string? Pan { get; set; }
        public string? Cvv2 { get; set; }
        public string? ExpireMonth { get; set; }
        public string? ExpireYear { get; set; }
        public string? Pin { get; set; }
        public string? Token { get; set; }

        public void Validate()
        {
            if (string.IsNullOrEmpty(Token))
            {
                if (string.IsNullOrEmpty(Pan) || Pan!.Length < 16)
                    throw new ArgumentException("Invalid PAN");
                if (string.IsNullOrEmpty(Cvv2) || Cvv2!.Length < 3)
                    throw new ArgumentException("Invalid CVV2");
                if (string.IsNullOrEmpty(Pin) || Pin!.Length < 4)
                    throw new ArgumentException("Invalid PIN");
            }
        }
    }

    public sealed record ChargePurchaseResult
    {
        public bool Success { get; set; }
        public string? ErrorCode { get; set; }
        public string? Message { get; set; }
        public string? UsedPhone { get; set; }
        public int RetryCount { get; set; }
        public string? FactorNumber { get; set; }
        public string? TransactionId { get; set; }
        public long? Amount { get; set; }
        public string? OperatorName { get; set; }
    }

    public sealed record ChargeOperator
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public List<ChargeAmount>? Amounts { get; set; }
    }

    public sealed record ChargeAmount
    {
        public long? Amount { get; set; }
        public string? Label { get; set; }
    }

    public sealed record NoSessionsEventArgs(bool WasEmptyFromStart, int DroppedCount, int RemainingCount);

    public sealed class IvaSessionManager
    {
        private readonly IvaOptions _opts;
        private readonly ISessionRepository _store;

        public IvaSessionManager(IvaOptions? options = null, ISessionRepository? store = null)
        {
            _opts = options ?? new IvaOptions();
            _store = store ?? new FileSessionRepository();
        }

        public Action<TokenResult>? OnRefresh { get; set; }
        public Action<NoSessionsEventArgs>? OnNoSessionsAvailable { get; set; }
        public Action<IvaAuthClient>? ConfigureService { get; set; }

        public IReadOnlyList<string> ListMobiles() => _store.ListPhones();
        public int Count => _store.ListPhones().Count;
        public void RemoveSession(string phone) => _store.Delete(phone);

        private IvaAuthClient NewService()
        {
            var client = new IvaAuthClient(_opts, sessions: _store);
            client.TokenRefreshed += t => OnRefresh?.Invoke(t);
            ConfigureService?.Invoke(client);
            return client;
        }

        public async Task<IvaAuthClient?> RandomLoginAsync(CancellationToken ct = default)
            => await NextWorkingServiceAsync(exclude: null, random: true, ct).ConfigureAwait(false);

        public async Task<ChargePurchaseResult> ChargeWalletAsync(
            string providerCode, long amount, string targetMobileNo,
            string pan, string cvv2, string expireMonth, string expireYear, string pin,
            CancellationToken ct = default)
        {
            var excluded = new HashSet<string>(StringComparer.Ordinal);
            var attempts = 0;
            var max = Math.Max(0, _opts.MaxChargeRetries);
            ChargePurchaseResult? last = null;

            while (true)
            {
                using var service = await NextWorkingServiceAsync(excluded, random: true, ct).ConfigureAwait(false);
                if (service is null)
                    return last ?? new ChargePurchaseResult { Success = false, ErrorCode = "no-accounts", Message = "هیچ اکانت فعالی موجود نیست" };

                var phone = service.CurrentPhone ?? "";

                var r = await service.BuyChargeAsync(
                    new ChargePurchaseRequest
                    {
                        Amount = amount,
                        TargetMobileNo = targetMobileNo,
                        ProviderId = providerCode,
                        Card = new CardPayment
                        {
                            Pan = pan,
                            Cvv2 = cvv2,
                            ExpireMonth = expireMonth,
                            ExpireYear = expireYear,
                            Pin = pin,
                        }
                    }, ct).ConfigureAwait(false);

                r.UsedPhone = phone;
                r.RetryCount = attempts;

                if (r.Success)
                    return r;

                last = r;

                if (!IvaAuthClient.Contains(_opts.RetryableStatusMessages, r.Message))
                    return r;

                if (IvaAuthClient.Contains(_opts.DailyLimitMessages, r.Message))
                    excluded.Add(phone);

                attempts++;
                if (attempts > max)
                    return r;

                await Task.Delay(_opts.ChargeRetryDelay, ct).ConfigureAwait(false);
            }
        }

        private async Task<IvaAuthClient?> NextWorkingServiceAsync(
            ISet<string>? exclude, bool random, CancellationToken ct)
        {
            var candidates = _store.ListPhones()
                .Where(m => exclude is null || !exclude.Contains(m))
                .ToList();

            var wasEmptyFromStart = candidates.Count == 0;
            if (random) Shuffle(candidates);

            var dropped = 0;
            foreach (var phone in candidates)
            {
                ct.ThrowIfCancellationRequested();

                var service = NewService();
                bool ok;
                try { ok = await service.TryResumeSessionAsync(phone, ct).ConfigureAwait(false); }
                catch { ok = false; }

                if (ok) return service;

                service.Dispose();
                _store.Delete(phone);
                dropped++;
            }

            OnNoSessionsAvailable?.Invoke(new NoSessionsEventArgs(wasEmptyFromStart, dropped, _store.ListPhones().Count));
            return null;
        }

        private static void Shuffle<T>(IList<T> list)
        {
            for (var i = list.Count - 1; i > 0; i--)
            {
                var j = RandomNumberGenerator.GetInt32(i + 1);
                (list[i], list[j]) = (list[j], list[i]);
            }
        }
    }
}