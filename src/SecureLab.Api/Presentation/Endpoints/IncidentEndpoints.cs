using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // ЛР 04: уся група вимагає автентифікації — анонім одержує 401 ще до endpoint.
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>()
            .ProducesValidationProblem();

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident");

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident");

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident");

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .WithTags("Incident comments")
            .RequireAuthorization();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        // ЛР 04: роль і id — лише з principal.
        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var isReporter = httpContext.User.IsInRole(DbSeeder.ReporterRole);
        if (!isAnalyst && !isReporter)
        {
            return Forbidden(); // Administrator: права на список матриця не надає.
        }

        if (!TryGetUserId(httpContext, out var userId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, userId, isAnalyst, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindForReadAsync(id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound(); // політика 404: чужий = неіснуючий
        }

        // Internal comments — лише для Analyst; ознака з principal, не з запиту.
        var includeInternal = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var details = await queries.GetDetailsAsync(id, includeInternal, cancellationToken);
        return details is null ? IncidentNotFound() : Results.Ok(details);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetSeveritySummaryAsync(parsedStatus, cancellationToken));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        // Без AsNoTracking: entity змінюватиметься.
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canUpdate = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Update);
        if (!canUpdate.Succeeded)
        {
            return Forbidden(); // бачить інцидент (Analyst), але редагувати не може
        }

        var errors = ValidateContent(request);
        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        // Зміна лише після обох дозволів і лише content fields.
        incident.Title = request.Title!.Trim();
        incident.Description = request.Description!.Trim();
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);

        return Results.Ok(new IncidentUpdatedResponse(
            incident.Id,
            incident.Title,
            incident.Description,
            incident.Severity.ToString(),
            incident.Status.ToString(),
            incident.UpdatedAtUtc));
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canDelete = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Delete);
        if (!canDelete.Succeeded)
        {
            return Forbidden();
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Інцидент уже в роботі",
                detail: "Видалити можна лише інцидент у статусі New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        db.Incidents.Remove(incident);
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserId(httpContext, out var userId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var audit = loggerFactory.CreateLogger("SecureLab.AuthorizationAudit");

        var canRead = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            LogDenied(audit, httpContext, userId, incident.Id);
            return IncidentNotFound();
        }

        var canTriage = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Triage);
        if (!canTriage.Succeeded)
        {
            LogDenied(audit, httpContext, userId, incident.Id);
            return Forbidden();
        }

        // Контекст рішення: перехід дозволено лише з New.
        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Недопустимий перехід статусу",
                detail: "Triage можливий лише для інциденту у статусі New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        // Наступний статус визначає сервер; тіло запиту не читається.
        var now = DateTimeOffset.UtcNow;
        var oldStatus = incident.Status;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = userId,
            OldStatus = oldStatus,
            NewStatus = IncidentStatus.Triaged,
            Note = "Triage",
            CreatedAtUtc = now
        });
        await db.SaveChangesAsync(cancellationToken);

        return Results.Ok(new IncidentTriageResponse(incident.Id, incident.Status.ToString()));
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        // Коментар завантажується разом із батьківським інцидентом.
        var comment = await db.IncidentComments
            .AsNoTracking()
            .Include(item => item.Incident)
            .Include(item => item.Author)
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (comment is null)
        {
            return CommentNotFound();
        }

        // Право на коментар = право читати батьківський інцидент (те саме рішення, що й для details).
        var canReadParent = await authorizationService.AuthorizeAsync(
            httpContext.User, comment.Incident, IncidentOperations.Read);
        if (!canReadParent.Succeeded)
        {
            return CommentNotFound();
        }

        // Internal comment — лише Analyst, як і в details-проєкції.
        if (comment.IsInternal && !httpContext.User.IsInRole(DbSeeder.AnalystRole))
        {
            return CommentNotFound();
        }

        return Results.Ok(new IncidentCommentResponse(
            comment.Id,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc));
    }

    // ЛР 04, політика 404: одна відповідь для чужого й неіснуючого id, без detail з id.
    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult CommentNotFound() => Results.Problem(
        title: "Коментар не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult Forbidden() => Results.Problem(
        title: "Доступ заборонено",
        statusCode: StatusCodes.Status403Forbidden);

    private static bool TryGetUserId(HttpContext httpContext, out Guid userId) =>
        Guid.TryParse(httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out userId);

    // Audit без пароля, cookie, token і тіла запиту. traceId — той самий, що в тілі Problem Details.
    private static void LogDenied(ILogger audit, HttpContext httpContext, Guid userId, Guid incidentId)
    {
        audit.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} "
            + "result={Result} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            userId,
            "incident.triage",
            incidentId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);
    }

    private static Dictionary<string, string[]> ValidateContent(UpdateIncidentRequest request)
    {
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrWhiteSpace(request.Title))
            errors["title"] = ["Назва обов'язкова."];
        else if (request.Title.Length > 160)
            errors["title"] = ["Назва не довша за 160 символів."];

        if (string.IsNullOrWhiteSpace(request.Description))
            errors["description"] = ["Опис обов'язковий."];
        else if (request.Description.Length > 4000)
            errors["description"] = ["Опис не довший за 4000 символів."];

        return errors;
    }
}
