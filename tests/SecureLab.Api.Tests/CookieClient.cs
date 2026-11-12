using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    public const string AntiforgeryHeader = "X-CSRF-TOKEN";

    // ЛР 06: після login клієнт одразу отримує request token у default header,
    // щоб старі mutation-тести перевіряли свою бізнес-умову, а не відмову antiforgery (пастка T-02).
    public static async Task<HttpClient> LoginAsync(
        this WebApplicationFactory<Program> factory, string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        await client.AttachAntiforgeryTokenAsync();
        return client;
    }

    // Отримує request token для поточної cookie-сесії й кладе його в header X-CSRF-TOKEN.
    public static async Task AttachAntiforgeryTokenAsync(this HttpClient client)
    {
        using var response = await client.GetAsync("/api/antiforgery/token");
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        client.DefaultRequestHeaders.Remove(AntiforgeryHeader);
        client.DefaultRequestHeaders.Add(AntiforgeryHeader, body!.Token);
    }

    private sealed record TokenResponse(string Token);
}