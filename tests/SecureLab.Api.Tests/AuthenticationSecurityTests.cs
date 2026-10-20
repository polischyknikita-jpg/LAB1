using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

// ЛР 03: власні безпекові регресійні сценарії автентифікації.
// Пароль береться лише зі змінної середовища; значення cookie і пароля не друкуються.
public sealed class AuthenticationSecurityTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string AuthCookieName = ".AspNetCore.Identity.Application";

    private static readonly string[] SensitiveFields =
        ["password", "confirmPassword", "passwordHash", "securityStamp", "concurrencyStamp", "cookie", "token"];

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Новий клієнт без cookie: HTTPS, без автоматичного переходу за redirect.
    private HttpClient NewClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = true
    });

    // A-01: анонімний запит до захищеного endpoint → 401, а не redirect чи HTML.
    [Fact]
    public async Task A01_Me_WithoutCookie_Returns401ProblemDetails_NotRedirect()
    {
        using var anonymous = NewClient();

        using var response = await anonymous.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    // A-02: login → /api/me повертає користувача з verified principal і лише безпечні поля.
    [Fact]
    public async Task A02_LoginThenMe_ReturnsVerifiedCurrentUser()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = await ReadJsonAsync(response);
        Assert.Equal(DbSeeder.AliceId, json.RootElement.GetProperty("id").GetGuid());
        Assert.Equal("alice", json.RootElement.GetProperty("userName").GetString());
        AssertNoSensitiveFields(json.RootElement);
    }

    // A-03: чинна cookie Alice + заголовок X-Demo-UserId Bob → /api/me лишається Alice.
    [Fact]
    public async Task A03_Me_WithForeignDemoHeader_KeepsCookiePrincipal()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = await ReadJsonAsync(response);
        var id = json.RootElement.GetProperty("id").GetGuid();
        Assert.Equal(DbSeeder.AliceId, id);
        Assert.NotEqual(DbSeeder.BobId, id);
    }

    // A-06: login → захищений запит → logout → той самий клієнт отримує 401.
    [Fact]
    public async Task A06_Logout_ThenSameClient_Gets401()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using (var before = await alice.GetAsync("/api/me"))
        {
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        }

        using var logout = await alice.PostAsync("/api/auth/logout", content: null);

        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        // Заголовків Set-Cookie кілька; шукаємо саме основну cookie за назвою, вміст не друкуємо.
        var clearsMainCookie = logout.Headers.TryGetValues("Set-Cookie", out var values)
            && values.Any(value => value.StartsWith(AuthCookieName + "=;", StringComparison.Ordinal));
        Assert.True(clearsMainCookie, "Logout must clear the main authentication cookie.");

        using var after = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    // A-07: невідомий користувач і хибний пароль мають однаковий зовнішній результат.
    [Fact]
    public async Task A07_UnknownUser_And_WrongPassword_LookTheSame()
    {
        using var client = NewClient();
        var unknownUser = "nouser" + Guid.NewGuid().ToString("N")[..8];
        // Хибний пароль формується локально і ніде не виводиться.
        var wrongPassword = StudyPassword + "-wrong";

        using var unknown = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = unknownUser, password = StudyPassword });
        using var wrong = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = wrongPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrong.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType, wrong.Content.Headers.ContentType?.MediaType);
        // traceId діагностичний і може відрізнятися, тому порівнюються лише стабільні поля.
        Assert.Equal(await StableShapeAsync(unknown), await StableShapeAsync(wrong));
        Assert.False(wrong.Headers.Contains("Set-Cookie"), "Failed login must not issue a cookie.");
    }

    // Flags: у HTTPS-сценарії cookie має httponly, secure, samesite=lax і є сеансовою.
    [Fact]
    public async Task CookieFlags_LoginOverHttps_HttpOnlySecureLaxSession()
    {
        using var client = NewClient();

        using var response = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(AuthCookieName + "=", StringComparison.Ordinal))
            .ToArray();
        // Перевірка за кількістю: значення cookie не потрапляє в повідомлення про помилку.
        Assert.True(matching.Length == 1, "Expected exactly one authentication cookie.");

        // Перша частина «назва=значення» відкидається й не читається.
        var attributes = matching[0].Split(';').Skip(1)
            .Select(part => part.Trim().ToLowerInvariant())
            .ToArray();
        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=lax", attributes);
        Assert.Contains("path=/", attributes);
        Assert.DoesNotContain(attributes,
            attribute => attribute.StartsWith("expires=", StringComparison.Ordinal)
                      || attribute.StartsWith("max-age=", StringComparison.Ordinal));
    }

    // Duplicate (добрий рівень): зайняте ім’я або email → 409 з однаковою відповіддю.
    [Fact]
    public async Task Register_Duplicate_Returns409_ForSameUserNameAndForSameEmail()
    {
        using var client = NewClient();
        var name = "reg" + Guid.NewGuid().ToString("N")[..8];
        var first = new
        {
            userName = name,
            email = name + "@example.test",
            displayName = "Тест дубль",
            password = StudyPassword
        };

        using var created = await client.PostAsJsonAsync("/api/auth/register", first);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        using (var json = await ReadJsonAsync(created))
        {
            AssertNoSensitiveFields(json.RootElement);
        }

        using var sameUserName = await client.PostAsJsonAsync(
            "/api/auth/register", first with { email = "other" + name + "@example.test" });
        using var sameEmail = await client.PostAsJsonAsync(
            "/api/auth/register", first with { userName = name + "b" });

        Assert.Equal(HttpStatusCode.Conflict, sameUserName.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, sameEmail.StatusCode);
        Assert.Equal("application/problem+json", sameUserName.Content.Headers.ContentType?.MediaType);
        // Відповідь не підказує, яке саме поле зайняте.
        Assert.Equal(await StableShapeAsync(sameUserName), await StableShapeAsync(sameEmail));
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync());

    private static void AssertNoSensitiveFields(JsonElement root)
    {
        foreach (var field in SensitiveFields)
        {
            Assert.False(root.TryGetProperty(field, out _), $"Unexpected sensitive field: {field}");
        }
    }

    // Стабільні поля Problem Details (без traceId): type, title, status, detail.
    private static async Task<string> StableShapeAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            return "<empty body>";
        }

        using var json = JsonDocument.Parse(body);
        var parts = new[] { "type", "title", "status", "detail" }
            .Select(name => json.RootElement.TryGetProperty(name, out var value)
                ? $"{name}={value}"
                : $"{name}=<absent>");
        return string.Join("; ", parts);
    }
}
