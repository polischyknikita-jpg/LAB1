using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 04: authorization test matrix (рівень «Добре», політика 404).
// Кожен користувач — окремий HttpClient зі своєю cookie. Пароль — лише зі змінної середовища.
// Позитивні mutation-тести працюють лише з інцидентами, які створюють самі, і прибирають їх у finally.
// Окремий host: тут багато login, тому ліміт частоти входу з ЛР 3 піднято лише для цього класу.
public sealed class Lab04ApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["LoginRateLimit:PermitLimit"] = "1000"
            }));
    }
}

public sealed class Lab04AuthorizationTests(Lab04ApiFactory factory)
    : IClassFixture<Lab04ApiFactory>
{
    private static readonly Guid BobNewIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private const string BobIncidentTitle = "Невідома спроба входу";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private async Task<HttpClient> LoginAsync(string userName)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password = StudyPassword });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException($"Study login failed: {(int)response.StatusCode} (credentials omitted).");
        }
        await client.AttachAntiforgeryTokenAsync(); // ЛР 06: request token для mutation-тестів
        return client;
    }

    // ---------- A-01 ----------

    [Fact]
    public async Task A01_Details_WithoutCookie_Returns401_NotRedirect()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

        using var response = await anonymous.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    // ---------- A-02 ----------

    [Fact]
    public async Task A02_Details_AsOwner_ReturnsOwnIncident_WithoutInternalComment()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Аліса Коваль", body);
        Assert.DoesNotContain(DbSeeder.AliceInternalCommentId.ToString(), body);
    }

    [Fact]
    public async Task A02_Update_AsOwner_ChangesContent()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A02");

        try
        {
            using var response = await alice.PutAsJsonAsync(
                $"/api/incidents/{id}", new { title = $"A02-updated-{id:N}", description = "Оновлено власником." });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var after = await ReadIncidentAsync(alice, id);
            Assert.Equal($"A02-updated-{id:N}", after["title"]!.GetValue<string>());
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-03 / A-03R ----------

    [Fact]
    public async Task A03_Details_AsNonOwner_ReturnsNotFound_WithoutBobData()
    {
        using var alice = await LoginAsync("alice");

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain(BobIncidentTitle, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task A03R_Details_AsAnalyst_ReturnsAliceIncident_WithInternalComment()
    {
        using var morgan = await LoginAsync("morgan");

        using var response = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(DbSeeder.AliceInternalCommentId.ToString(), body);
    }

    // ---------- A-04 ----------

    [Fact]
    public async Task A04_Update_AsNonOwner_ReturnsNotFound_AndDoesNotChangeIncident()
    {
        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");
        var before = await ReadIncidentAsync(bob, DbSeeder.BobIncidentId);

        using var response = await alice.PutAsJsonAsync(
            $"/api/incidents/{DbSeeder.BobIncidentId}",
            new { title = "Changed by Alice", description = "Спроба змінити чужий інцидент." });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var after = await ReadIncidentAsync(bob, DbSeeder.BobIncidentId);
        Assert.Equal(before["title"]!.GetValue<string>(), after["title"]!.GetValue<string>());
        Assert.Equal(before["description"]!.GetValue<string>(), after["description"]!.GetValue<string>());
    }

    [Fact]
    public async Task A04_Delete_AsNonOwner_ReturnsNotFound_AndIncidentStillExists()
    {
        using var alice = await LoginAsync("alice");
        using var bob = await LoginAsync("bob");
        var id = await CreateIncidentAsync(bob, "A04-delete");

        try
        {
            using var response = await alice.DeleteAsync($"/api/incidents/{id}");

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            using var check = await bob.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.OK, check.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-05 ----------

    [Fact]
    public async Task A05_List_AsAlice_ContainsOnlyOwnIncidents()
    {
        using var alice = await LoginAsync("alice");

        var list = await alice.GetFromJsonAsync<JsonArray>("/api/incidents");
        var ids = list!.Select(item => item!["id"]!.GetValue<Guid>()).ToList();

        Assert.Contains(DbSeeder.AliceIncidentId, ids);
        Assert.DoesNotContain(DbSeeder.BobIncidentId, ids);
        Assert.DoesNotContain(BobNewIncidentId, ids);
    }

    // ---------- A-06 / A-09 (відмова, audit див. у виводі API) ----------

    [Fact]
    public async Task A06_Triage_AsReporter_ReturnsForbidden_AndStatusStaysNew()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A06");

        try
        {
            // Підставлена роль у тілі не повинна нічого змінити.
            using var response = await alice.PostAsJsonAsync(
                $"/api/incidents/{id}/triage", new { role = "Analyst", status = "Triaged" });

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var after = await ReadIncidentAsync(alice, id);
            Assert.Equal("New", after["status"]!.GetValue<string>());
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-07 ----------

    [Fact]
    public async Task A07_Triage_AsAnalyst_FromNew_ReturnsTriaged_AndRoleGivesNoExtraRights()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");
        var id = await CreateIncidentAsync(alice, "A07");

        try
        {
            using var triage = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.OK, triage.StatusCode);
            var after = await ReadIncidentAsync(alice, id);
            Assert.Equal("Triaged", after["status"]!.GetValue<string>());

            // Контекст: повторний triage не з New — 409.
            using var again = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
            Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

            // Роль Analyst не дає права редагувати чужий інцидент.
            using var edit = await morgan.PutAsJsonAsync(
                $"/api/incidents/{id}", new { title = "Changed by Morgan", description = "Немає права." });
            Assert.Equal(HttpStatusCode.Forbidden, edit.StatusCode);
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-08a ----------

    [Fact]
    public async Task A08a_Update_WithForgedProtectedFields_ChangesOnlyContent()
    {
        using var alice = await LoginAsync("alice");
        var id = await CreateIncidentAsync(alice, "A08a");

        try
        {
            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = $"A08a-updated-{id:N}",
                description = "Оновлено з підставленими полями.",
                status = "Closed",
                severity = "Critical",
                ownerUserId = DbSeeder.BobId,
                role = "Analyst"
            });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var after = await ReadIncidentAsync(alice, id);
            Assert.Equal($"A08a-updated-{id:N}", after["title"]!.GetValue<string>());
            Assert.Equal("New", after["status"]!.GetValue<string>());
            Assert.Equal("Low", after["severity"]!.GetValue<string>());
            Assert.Equal("Аліса Коваль", after["ownerDisplayName"]!.GetValue<string>());
        }
        finally
        {
            await DeleteIncidentAsync(id);
        }
    }

    // ---------- A-10 ----------

    [Fact]
    public async Task A10_Details_ForeignAndUnknownId_AreIndistinguishable()
    {
        using var alice = await LoginAsync("alice");

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.ToString(),
            foreign.Content.Headers.ContentType?.ToString());

        var foreignBody = await foreign.Content.ReadFromJsonAsync<JsonObject>();
        var unknownBody = await unknown.Content.ReadFromJsonAsync<JsonObject>();
        foreignBody!.Remove("traceId"); // єдина дозволена відмінність
        unknownBody!.Remove("traceId");
        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
    }

    // ---------- A-12 ----------

    [Fact]
    public async Task A12_Comment_ForeignOrInternal_ReturnsNotFound_ForReporter()
    {
        using var alice = await LoginAsync("alice");
        using var morgan = await LoginAsync("morgan");

        using var foreign = await alice.GetAsync($"/api/incident-comments/{DbSeeder.BobCommentId}");
        using var @internal = await alice.GetAsync($"/api/incident-comments/{DbSeeder.AliceInternalCommentId}");
        using var analyst = await morgan.GetAsync($"/api/incident-comments/{DbSeeder.AliceInternalCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, @internal.StatusCode);
        Assert.DoesNotContain("Внутрішня примітка", await @internal.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, analyst.StatusCode);
    }

    // ---------- helpers ----------

    private static async Task<Guid> CreateIncidentAsync(HttpClient client, string prefix)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"{prefix}-{Guid.NewGuid():N}",
            description = "Штучний запис для тесту авторизації ЛР 4.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonObject>();
        return json!["id"]!.GetValue<Guid>();
    }

    private static async Task<JsonObject> ReadIncidentAsync(HttpClient client, Guid id)
    {
        using var response = await client.GetAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonObject>())!;
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
