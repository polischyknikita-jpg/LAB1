using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentCreationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    // T-02: некоректний DTO (порожній title і severity "7") дає 400 Problem Details.
    [Fact]
    public async Task Post_WithInvalidDto_Returns400WithFieldErrors()
    {
        var body = new
        {
            title = "   ",
            description = "Штучний опис для перевірки валідації.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        using var response = await _client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json",
            response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var errors = document.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("title", out _));
        Assert.True(errors.TryGetProperty("severity", out _));

        // Безпечна помилка: без внутрішніх деталей.
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
    }

    // T-03: другий активний інцидент з тим самим title дає 409.
    [Fact]
    public async Task Post_WithDuplicateActiveTitle_Returns409()
    {
        // Унікальний title, щоб тест можна було повторювати на тій самій БД.
        var title = $"Regression-{Guid.NewGuid():N}";
        var body = new
        {
            title,
            description = "Штучний запис для перевірки предметного конфлікту.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var first = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal("application/problem+json",
                second.Content.Headers.ContentType?.MediaType);

            var json = await second.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            Assert.False(document.RootElement.TryGetProperty("errors", out _));
            Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        }
        finally
        {
            // Прибираємо лише власні записи, навіть якщо assertion упав.
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
        }
    }
}