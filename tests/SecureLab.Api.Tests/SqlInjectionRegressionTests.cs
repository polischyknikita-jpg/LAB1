using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;

namespace SecureLab.Api.Tests;

// S-02 (ЛР 2), автоматизовано в ЛР 6: значення q з SQL-метасимволами шукається як звичайний текст
// і не змінює структуру SQL-запиту; sortBy поза allowlist не доходить до SQL (400).
public sealed class SqlInjectionRegressionTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task S02_Search_WithSqlMetacharacters_IsLiteral_AndUnknownSortBy_Returns400()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        // Позитивна частина: звичайний пошук повертає записи.
        using var normal = await alice.GetAsync("/api/incidents/search?q=");
        Assert.Equal(HttpStatusCode.OK, normal.StatusCode);
        var all = await normal.Content.ReadFromJsonAsync<JsonArray>();
        Assert.NotEmpty(all!);

        // Негативна частина: класичний payload не перетворюється на умову "завжди true".
        using var injected = await alice.GetAsync(
            "/api/incidents/search?q=" + Uri.EscapeDataString("' OR '1'='1"));
        Assert.Equal(HttpStatusCode.OK, injected.StatusCode);
        var found = await injected.Content.ReadFromJsonAsync<JsonArray>();
        Assert.Empty(found!);

        // sortBy поза allowlist відхиляється до SQL.
        using var badSort = await alice.GetAsync(
            "/api/incidents/search?q=test&sortBy=" + Uri.EscapeDataString("title; DROP TABLE incidents"));
        Assert.Equal(HttpStatusCode.BadRequest, badSort.StatusCode);
    }
}
