using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 06, F-02 / REG-SEARCH-01: пошук дотримується матриці доступу ЛР 4:
// анонім → 401; Reporter бачить лише власні інциденти; Analyst — усі.
public sealed class SearchAuthorizationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task RegSearch01_RequiresLogin_ReporterSeesOnlyOwn_AnalystSeesAll()
    {
        // 1) Анонім: 401 без даних.
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false
        });
        using (var anon = await anonymous.GetAsync("/api/incidents/search?q="))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, anon.StatusCode);
        }

        // 2) Reporter alice: свій інцидент є, інциденту bob немає.
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var aliceIds = await SearchIdsAsync(alice);
        Assert.Contains(DbSeeder.AliceIncidentId, aliceIds);
        Assert.DoesNotContain(DbSeeder.BobIncidentId, aliceIds);

        // 3) Positive: Analyst morgan бачить обидва.
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        var morganIds = await SearchIdsAsync(morgan);
        Assert.Contains(DbSeeder.AliceIncidentId, morganIds);
        Assert.Contains(DbSeeder.BobIncidentId, morganIds);
    }

    private static async Task<List<Guid>> SearchIdsAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/incidents/search?q=");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = await response.Content.ReadFromJsonAsync<JsonArray>();
        return items!.Select(item => item!["id"]!.GetValue<Guid>()).ToList();
    }
}
