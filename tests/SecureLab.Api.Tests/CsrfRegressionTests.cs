using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 06, REG-CSRF-01: змінювальний запит із чинною cookie, але без коректного request token,
// відхиляється до handler і не змінює стан; той самий запит із token проходить.
public sealed class CsrfRegressionTests(Lab04ApiFactory factory) : IClassFixture<Lab04ApiFactory>
{
    private const string RejectedTitle = "Antiforgery token is missing or invalid.";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task RegCsrf01_UpdateIncident_WithoutOrInvalidToken_Rejected_WithToken_Succeeds()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var id = await CreateIncidentAsync(alice);

        try
        {
            var before = await ReadTitleAsync(alice, id);
            var changed = $"REG-CSRF-01-{id:N}";

            // 1) Без request token: cookie є, token немає.
            alice.DefaultRequestHeaders.Remove(CookieClient.AntiforgeryHeader);
            using (var missing = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                       new { title = changed, description = "Спроба без request token." }))
            {
                await AssertRejectedAsync(missing);
            }
            Assert.Equal(before, await ReadTitleAsync(alice, id));

            // 2) Підроблений request token.
            alice.DefaultRequestHeaders.Add(CookieClient.AntiforgeryHeader, "forged-token-value");
            using (var forged = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                       new { title = changed, description = "Спроба з підробленим token." }))
            {
                await AssertRejectedAsync(forged);
            }
            Assert.Equal(before, await ReadTitleAsync(alice, id));

            // 3) Коректний request token: зміна проходить.
            await alice.AttachAntiforgeryTokenAsync();
            using (var allowed = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                       new { title = changed, description = "Зміна з request token." }))
            {
                Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
            }
            Assert.Equal(changed, await ReadTitleAsync(alice, id));
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    private static async Task AssertRejectedAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal(RejectedTitle, problem!["title"]!.GetValue<string>());
    }

    private static async Task<Guid> CreateIncidentAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"REG-CSRF-{Guid.NewGuid():N}",
            description = "Штучний запис для REG-CSRF-01.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonObject>();
        return json!["id"]!.GetValue<Guid>();
    }

    private static async Task<string> ReadTitleAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonObject>();
        return json!["title"]!.GetValue<string>();
    }

    private async Task DeleteIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.IncidentStatusHistory.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.IncidentComments.Where(item => item.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(item => item.Id == id).ExecuteDeleteAsync();
    }
}
