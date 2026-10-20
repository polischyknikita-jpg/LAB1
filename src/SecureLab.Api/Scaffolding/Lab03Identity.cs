using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    // Контракт register (ЛР 03). Межі узгоджено з моделлю БД:
    // DisplayName — varchar(120), UserName/Email — varchar(256).
    private const int UserNameMinLength = 3;
    private const int UserNameMaxLength = 64;
    private const int EmailMaxLength = 256;
    private const int DisplayNameMaxLength = 120;
    // Обмеження зверху, щоб довгий рядок не робив хешування надто дорогим.
    private const int PasswordMaxLength = 128;

    // Категорія журналу для подій автентифікації.
    private const string AuthEventsCategory = "SecureLab.AuthEvents";

    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", RegisterAsync);
        // ЛР 03 (добрий рівень): login з подіями автентифікації та обмеженням частоти.
        app.MapPost("/api/auth/login", async (
            LoginInput input, SignInManager<ApplicationUser> signIn,
            ILoggerFactory loggers, HttpContext httpContext) =>
        {
            var events = loggers.CreateLogger(AuthEventsCategory);
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                LogAuthEvent(events, "login", "failure", null, httpContext);
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            if (!result.Succeeded)
            {
                // Однаковий 401 для невідомого користувача і хибного пароля;
                // у подію не записується ні введене ім'я, ні причина відмови.
                LogAuthEvent(events, "login", "failure", null, httpContext);
                return Results.Unauthorized();
            }

            var user = await signIn.UserManager.FindByNameAsync(input.UserName);
            LogAuthEvent(events, "login", "success", user?.Id, httpContext);
            return Results.NoContent();
        }).RequireRateLimiting("login");
        // ЛР 03 (добрий рівень): стандартний sign-out Identity; Set-Cookie наказує браузеру видалити cookie.
        app.MapPost("/api/auth/logout", async (
            SignInManager<ApplicationUser> signIn, ILoggerFactory loggers, HttpContext httpContext) =>
        {
            Guid? userId = Guid.TryParse(
                httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id) ? id : null;
            await signIn.SignOutAsync();
            LogAuthEvent(loggers.CreateLogger(AuthEventsCategory), "logout", "success", userId, httpContext);
            return Results.NoContent();
        });
        // ЛР 03: поточний користувач лише з verified principal; X-Demo-UserId не використовується.
        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    // Подія автентифікації: тип, результат, id користувача (лише якщо його підтверджено), trace id.
    // Password, cookie, hash, token, заголовок Authorization і тіло запиту сюди не потрапляють.
    private static void LogAuthEvent(
        ILogger events, string eventType, string result, Guid? userId, HttpContext httpContext)
    {
        var level = result == "success" ? LogLevel.Information : LogLevel.Warning;
        events.Log(level,
            "Auth event {EventType}: result {Result}, user {UserId}, trace {TraceId}",
            eventType, result, userId?.ToString() ?? "-", httpContext.TraceIdentifier);
    }

    // ЛР 03, етап 3: id береться з claim NameIdentifier перевіреної cookie.
    private static async Task<IResult> GetCurrentUser(HttpContext httpContext, SecureLabDbContext db)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            // Автентифікований principal без id — помилка конфігурації, а не привід брати id від клієнта.
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;
        // DisplayName читається з БД саме за перевіреним id.
        var user = await db.Users.FindAsync(verifiedUserId);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        return Results.Ok(new CurrentUserResponse(verifiedUserId, userName, user.DisplayName, role));
    }

    // ЛР 03, етап 2: register із перевіркою контракту та безпечною відповіддю.
    private static async Task<IResult> RegisterAsync(
        RegistrationInput input, UserManager<ApplicationUser> users)
    {
        var errors = ValidateRegistration(input);
        if (errors.Count > 0)
            return Results.ValidationProblem(errors, title: "Registration failed");

        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = input.UserName!.Trim(),
            Email = input.Email!.Trim(),
            DisplayName = input.DisplayName!.Trim()
        };

        var result = await users.CreateAsync(user, input.Password!);
        if (!result.Succeeded)
        {
            var codes = result.Errors.Select(error => error.Code).ToHashSet(StringComparer.Ordinal);
            if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Registration conflict",
                    detail: "Обліковий запис з такими даними вже існує.");
            }

            return Results.ValidationProblem(MapIdentityErrors(codes), title: "Registration failed");
        }

        var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
        if (!role.Succeeded)
        {
            await users.DeleteAsync(user);
            throw new InvalidOperationException("Default role assignment failed.");
        }

        return Results.Created("/api/me", new RegistrationResponse(user.Id, user.UserName!, user.DisplayName));
    }

    private static Dictionary<string, string[]> ValidateRegistration(RegistrationInput input)
    {
        var errors = new Dictionary<string, string[]>();

        var userName = input.UserName?.Trim();
        if (string.IsNullOrEmpty(userName)
            || userName.Length < UserNameMinLength
            || userName.Length > UserNameMaxLength
            || !userName.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-'))
        {
            errors["userName"] = [$"Ім’я користувача: {UserNameMinLength}–{UserNameMaxLength} символів; лише латинські літери, цифри, '.', '_' або '-'."];
        }

        var email = input.Email?.Trim();
        if (string.IsNullOrEmpty(email) || email.Length > EmailMaxLength)
        {
            errors["email"] = [$"Email обов’язковий, не довший за {EmailMaxLength} символів."];
        }

        var displayName = input.DisplayName?.Trim();
        if (string.IsNullOrEmpty(displayName)
            || displayName.Length > DisplayNameMaxLength
            || displayName.Any(char.IsControl))
        {
            errors["displayName"] = [$"Відображуване ім’я обов’язкове, до {DisplayNameMaxLength} символів, без керівних символів."];
        }

        if (string.IsNullOrEmpty(input.Password) || input.Password.Length > PasswordMaxLength)
        {
            errors["password"] = [$"Пароль обов’язковий, не довший за {PasswordMaxLength} символів."];
        }

        return errors;
    }

    private static Dictionary<string, string[]> MapIdentityErrors(HashSet<string> codes)
    {
        var errors = new Dictionary<string, string[]>();

        if (codes.Any(code => code.StartsWith("Password", StringComparison.Ordinal)))
        {
            errors["password"] = ["Пароль: щонайменше 10 символів, велика й мала латинські літери, цифра та символ, що не є літерою чи цифрою."];
        }

        if (codes.Contains("InvalidEmail"))
        {
            errors["email"] = ["Некоректний формат email."];
        }

        if (codes.Contains("InvalidUserName"))
        {
            errors["userName"] = ["Ім’я користувача містить недозволені символи."];
        }

        if (errors.Count == 0)
        {
            errors["request"] = ["Реєстрацію не виконано."];
        }

        return errors;
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);
public sealed record CurrentUserResponse(Guid Id, string UserName, string DisplayName, string Role);
public sealed record LoginInput(string? UserName, string? Password);
