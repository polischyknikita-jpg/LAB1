using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Hosting;

namespace SecureLab.Api.Tests;

// ЛР 06 (добрий рівень): обмеження пошуку — quota, 429, окремий partition іншого
// користувача й відновлення після вікна. Окремий host із малою quota і коротким вікном.
public sealed class SearchRateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const int PermitLimit = 2;
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(3);

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task Search_OverQuota_Returns429_OtherUserUnaffected_ThenRecovers()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SearchRateLimit:PermitLimit"] = PermitLimit.ToString(),
                    ["SearchRateLimit:WindowSeconds"] = Window.TotalSeconds.ToString()
                })));
        using var alice = await host.LoginAsync("alice", StudyPassword);
        using var bob = await host.LoginAsync("bob", StudyPassword);

        // 1) У межах quota пошук працює.
        for (var i = 0; i < PermitLimit; i++)
        {
            using var ok = await alice.GetAsync("/api/incidents/search?q=test");
            Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        }

        // 2) Наступний запит alice вичерпує quota.
        using (var limited = await alice.GetAsync("/api/incidents/search?q=test"))
        {
            Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        }

        // 3) Інший partition (bob) не заблоковано.
        using (var other = await bob.GetAsync("/api/incidents/search?q=test"))
        {
            Assert.Equal(HttpStatusCode.OK, other.StatusCode);
        }

        // 4) Після вікна alice знову може шукати.
        await Task.Delay(Window + TimeSpan.FromSeconds(1.5));
        using (var recovered = await alice.GetAsync("/api/incidents/search?q=test"))
        {
            Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
        }
    }
}
