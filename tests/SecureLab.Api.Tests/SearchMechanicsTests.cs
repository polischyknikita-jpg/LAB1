using System.Net;

namespace SecureLab.Api.Tests;

// ЛР 06 (F-02): пошук тепер вимагає входу, тому механіку перевіряємо від імені alice.
public sealed class SearchMechanicsTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task Search_ReturnsJson()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync("/api/incidents/search?q=навчальн");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
    }
}
