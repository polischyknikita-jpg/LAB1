using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace SecureLab.Api.Tests;

// ЛР 03 (добрий рівень): обмеження частоти login — 429 і відновлення після вікна.
// Окремий host із коротким вікном: лічильники належать host, а не HttpClient.
// У тестовому сервері RemoteIpAddress = null, тому всі клієнти host-а мають спільний ключ "unknown".
public sealed class LoginRateLimitTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const int PermitLimit = 3;
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(3);

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private WebApplicationFactory<Program> FreshHost() => factory.WithWebHostBuilder(builder =>
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["LoginRateLimit:PermitLimit"] = PermitLimit.ToString(),
                ["LoginRateLimit:WindowSeconds"] = Window.TotalSeconds.ToString()
            })));

    private static HttpClient NewClient(WebApplicationFactory<Program> host) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    [Fact]
    public async Task Login_OverLimit_Returns429ForAnyUser_ThenRecoversAfterWindow()
    {
        using var host = FreshHost();
        using var attacker = NewClient(host);
        using var other = NewClient(host);
        // Хибний пароль формується локально і ніде не виводиться.
        var wrongPassword = StudyPassword + "-wrong";

        // У межах ліміту: звичайні 401.
        for (var i = 0; i < PermitLimit; i++)
        {
            using var denied = await attacker.PostAsJsonAsync(
                "/api/auth/login", new { userName = "alice", password = wrongPassword });
            Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        }

        // Понад ліміт: 429 навіть для правильного пароля — квоту вичерпано для ключа.
        using var limitedReal = await other.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedReal.StatusCode);
        Assert.False(limitedReal.Headers.Contains("Set-Cookie"), "Rate-limited login must not issue a cookie.");

        // Для невідомого користувача — той самий 429: існування акаунта не розкривається.
        using var limitedUnknown = await other.PostAsJsonAsync(
            "/api/auth/login", new { userName = "nouser" + Guid.NewGuid().ToString("N")[..8], password = wrongPassword });
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedUnknown.StatusCode);
        Assert.Equal(limitedReal.Content.Headers.ContentType?.MediaType,
            limitedUnknown.Content.Headers.ContentType?.MediaType);

        // Новий host має власні лічильники.
        using var independentHost = FreshHost();
        using var fresh = NewClient(independentHost);
        using var freshReply = await fresh.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, freshReply.StatusCode);

        // Після повного вікна з запасом — знову звичайна обробка.
        await Task.Delay(Window + TimeSpan.FromMilliseconds(500));
        using var recovered = await other.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }
}
