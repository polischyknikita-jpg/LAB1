using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 03, етап 4: захищене створення інциденту і власник лише з verified principal.
// Виконавець — Bob: старий код записував сталу Alice, тому Bob відрізняє константу від principal.
public sealed class IncidentOwnershipTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // A-01 для create (CP-03): анонімний POST → 401 і запис не створюється.
    [Fact]
    public async Task Post_WithoutCookie_Returns401_AndCreatesNothing()
    {
        using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        var title = $"Anon-{Guid.NewGuid():N}";

        try
        {
            using var response = await anonymous.PostAsJsonAsync("/api/incidents", NewBody(title));

            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.Null(await FindOwnerAsync(title));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-04: authenticated create без owner у DTO → owner = principal (Bob).
    [Fact]
    public async Task A04_BobCreatesWithoutOwner_OwnerIsBob()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        var title = $"A04-{Guid.NewGuid():N}";

        try
        {
            using var response = await bob.PostAsJsonAsync("/api/incidents", NewBody(title));

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var createdId = await ReadCreatedIdAsync(response);
            Assert.Equal(DbSeeder.BobId, await FindOwnerByIdAsync(createdId));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // A-05: Bob додає в JSON чужий ownerUserId (Alice) → owner лишається Bob.
    [Fact]
    public async Task A05_BobSendsAliceAsOwner_OwnerStaysBob()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        var title = $"A05-{Guid.NewGuid():N}";
        var forged = new
        {
            title,
            description = "Штучний запис: спроба підмінити власника.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
            ownerUserId = DbSeeder.AliceId
        };

        try
        {
            using var response = await bob.PostAsJsonAsync("/api/incidents", forged);

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var createdId = await ReadCreatedIdAsync(response);
            var owner = await FindOwnerByIdAsync(createdId);
            Assert.Equal(DbSeeder.BobId, owner);
            Assert.NotEqual(DbSeeder.AliceId, owner);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    private static object NewBody(string title) => new
    {
        title,
        description = "Штучний запис для перевірки власника.",
        severity = "Low",
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    // Id нового запису з безпечної відповіді; owner у відповіді не віддається.
    private static async Task<Guid> ReadCreatedIdAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(json.RootElement.TryGetProperty("ownerUserId", out _));
        return json.RootElement.GetProperty("id").GetGuid();
    }

    // Фактичний власник читається з БД саме для нового запису, не для seed.
    private async Task<Guid?> FindOwnerByIdAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => (Guid?)item.OwnerUserId)
            .SingleOrDefaultAsync();
    }

    private async Task<Guid?> FindOwnerAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AsNoTracking()
            .Where(item => item.Title == title)
            .Select(item => (Guid?)item.OwnerUserId)
            .SingleOrDefaultAsync();
    }

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }
}
