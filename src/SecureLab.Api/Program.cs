using Microsoft.AspNetCore.Antiforgery;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using SecureLab.Api.Scaffolding;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();

builder.AddLab03Identity();
// ЛР 06: стандартний antiforgery ASP.NET Core; request token клієнт повертає в header X-CSRF-TOKEN.
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "securelab-af";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
});

builder.Services.AddSingleton<IAuthorizationHandler, IncidentAuthorizationHandler>();

// ЛР 03 (добрий рівень): обмеження частоти спроб входу.
// Ключ — IP-адреса клієнта; ліміт і вікно читаються з конфігурації під час запиту
// (за замовчуванням 10 спроб за 60 секунд), щоб тест міг задати короткі значення.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        var loggers = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
        var path = context.HttpContext.Request.Path;
        if (path.StartsWithSegments("/api/auth/login"))
        {
            // Подія без credentials: лише тип, результат і trace id.
            loggers.CreateLogger("SecureLab.AuthEvents").LogWarning(
                "Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
                "login", "rate_limited", "-", context.HttpContext.TraceIdentifier);
        }
        else
        {
            // ЛР 06: інші обмежені маршрути; query string (q) не логуємо.
            loggers.CreateLogger("SecureLab.RateLimit").LogWarning(
                "Rate limit rejected: path {Path}, trace {TraceId}",
                path.Value, context.HttpContext.TraceIdentifier);
        }
        return ValueTask.CompletedTask;
    };
    options.AddPolicy("login", httpContext =>
    {
        var configuration = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        var permitLimit = configuration.GetValue("LoginRateLimit:PermitLimit", 10);
        var windowSeconds = configuration.GetValue("LoginRateLimit:WindowSeconds", 60);
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromSeconds(windowSeconds),
                QueueLimit = 0
            });
    });
    // ЛР 06 (добрий рівень): обмеження пошуку. Ключ — id перевіреного користувача
    // з cookie-сеансу (UseRateLimiter стоїть після UseAuthentication); для анонімного запиту — IP.
    // Довільний header клієнта ключем не є. За замовчуванням 5 запитів за 30 секунд.
    options.AddPolicy("search", httpContext =>
    {
        var configuration = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        var permitLimit = configuration.GetValue("SearchRateLimit:PermitLimit", 5);
        var windowSeconds = configuration.GetValue("SearchRateLimit:WindowSeconds", 30);
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var partitionKey = userId is not null
            ? $"user:{userId}"
            : $"ip:{httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown"}";
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: partitionKey,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromSeconds(windowSeconds),
                QueueLimit = 0
            });
    });
});
// LR 05: study CORS policy, Development only, exact allowlist with one origin.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                .WithMethods("GET")
                .WithHeaders("X-Lab-Cors-Probe")
                .AllowCredentials();
        });
    });
}
var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

app.UseExceptionHandler();
app.UseStatusCodePages();

// LR 05: CSP from the actual client resources; Scalar UI (Development only) is excluded.
var csp = "default-src 'self'; frame-ancestors 'none'";

app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");

    var isDevelopmentApiReference =
        app.Environment.IsDevelopment()
        && context.Request.Path.StartsWithSegments("/scalar");

    if (!isDevelopmentApiReference)
    {
        context.Response.Headers["Content-Security-Policy"] = csp;
    }

    await next(context);
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}
app.UseRouting();
if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}


app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

// ЛР 06: same-origin видача request token для поточного principal; cookie-частину ставить framework.
app.MapGet("/api/antiforgery/token", (IAntiforgery antiforgery, HttpContext httpContext) =>
{
    var tokens = antiforgery.GetAndStoreTokens(httpContext);
    return Results.Ok(new { token = tokens.RequestToken });
}).RequireAuthorization();
app.MapIncidentEndpoints();
app.MapLab03Identity();
app.MapLab02Endpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;
