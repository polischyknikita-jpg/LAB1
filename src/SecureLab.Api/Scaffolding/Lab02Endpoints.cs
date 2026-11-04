using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            // Значення q стає параметром; % і _ усередині q шукаються буквально.
            var pattern = "%" + EscapeLike(q ?? "") + "%";

            // Одна умова з явним OR: збіг у Title або в Description.
            var found = db.Incidents.AsNoTracking()
                .Where(item => EF.Functions.ILike(item.Title, pattern, "\\")
                            || EF.Functions.ILike(item.Description, pattern, "\\"));

            // Allowlist: клієнт лише обирає одну з написаних сервером гілок.
            IQueryable<Incident>? ordered = sortBy switch
            {
                null or "" or "createdAtUtc" => found
                    .OrderByDescending(item => item.CreatedAtUtc)
                    .ThenBy(item => item.Id),
                "severity" => found
                    .OrderBy(item => item.Severity == IncidentSeverity.Critical ? 0
                        : item.Severity == IncidentSeverity.High ? 1
                        : item.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(item => item.Id),
                "status" => found
                    .OrderBy(item => item.Status == IncidentStatus.New ? 0
                        : item.Status == IncidentStatus.Triaged ? 1
                        : item.Status == IncidentStatus.InProgress ? 2
                        : item.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(item => item.Id),
                _ => null
            };

            // Невідоме sortBy не доходить до SQL.
            if (ordered is null)
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });

            var items = await ordered
                .Take(50)
                .Select(item => new IncidentSearchItemResponse(
                    item.Id, item.Title, item.Description,
                    item.Severity.ToString(), item.Status.ToString(), item.CreatedAtUtc))
                .ToListAsync(ct);
            return Results.Ok(items);
        });

        // ЛР 03: створення доступне лише автентифікованому користувачу;
        // власник береться з verified principal, а не з JSON чи заголовка.
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, HttpContext httpContext, SecureLabDbContext db, CancellationToken ct) =>
        {
            // Ідентифікатор поточного користувача — лише з claim перевіреної cookie.
            var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(userId, out var verifiedUserId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

            // Час фіксуємо один раз на початку обробки.
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            // title: обов'язковий після Trim; довжину міряємо до Trim.
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Назва обов'язкова."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Назва не довша за 160 символів."];

            // description: те саме, межа 4000.
            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Опис обов'язковий."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Опис не довший за 4000 символів."];

            // severity: TryParse + IsDefined, щоб "7" не пройшло.
            var severityIsValid =
                Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
                && Enum.IsDefined(severity);
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

            // occurredAtUtc: обов'язковий і не пізніше now + 5 хвилин.
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["Час інциденту обов'язковий."];
            else if (request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Час інциденту не може бути в майбутньому."];

            // Нормалізація — один раз.
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // Cross-field (добрий рівень, T-09).
            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
            {
                errors["description"] = ["Для High або Critical опис має містити щонайменше 40 символів."];
            }

            // Усі помилки контракту — одна відповідь 400, ще до БД.
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // Предметний конфлікт (добрий рівень, T-03): регістр враховується, Closed не блокує.
            var duplicateExists = await db.Incidents.AnyAsync(item =>
                item.Title == title &&
                (item.Status == IncidentStatus.New
                 || item.Status == IncidentStatus.Triaged
                 || item.Status == IncidentStatus.InProgress
                 || item.Status == IncidentStatus.Resolved), ct);
            if (duplicateExists)
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Інцидент уже існує",
                    detail: "Активний інцидент з такою назвою вже зареєстровано.");

            // Server-managed поля встановлює лише сервер; власник — verified principal.
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = verifiedUserId,
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime(),
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };
            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            // Response DTO — лише поля зовнішнього контракту.
            var response = new CreatedIncidentResponse(
                incident.Id, incident.Title, incident.Description,
                incident.Severity.ToString(), incident.Status.ToString(),
                incident.OccurredAtUtc, incident.CreatedAtUtc, incident.UpdatedAtUtc);
            return Results.Created($"/api/incidents/{incident.Id}", response);
        }).RequireAuthorization(policy => policy.RequireRole(DbSeeder.ReporterRole, DbSeeder.AnalystRole));
    }

    // Спершу екрануємо саму \, потім % і _ — так їх ILIKE сприймає буквально.
    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}

// Request DTO не містить OwnerUserId, Id, Status чи Role: ними керує сервер.
public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id, string Title, string Description, string Severity, string Status,
    DateTimeOffset OccurredAtUtc, DateTimeOffset CreatedAtUtc, DateTimeOffset UpdatedAtUtc);

public sealed record IncidentSearchItemResponse(
    Guid Id, string Title, string Description, string Severity, string Status,
    DateTimeOffset CreatedAtUtc);