using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// ЛР 04: операції над одним інцидентом. Правило для кожної — лише в IncidentAuthorizationHandler.
public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Read = new() { Name = nameof(Read) };
    public static readonly OperationAuthorizationRequirement Update = new() { Name = nameof(Update) };
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = nameof(Delete) };
    public static readonly OperationAuthorizationRequirement Triage = new() { Name = nameof(Triage) };
}

// ЛР 04: централізоване рішення "principal + інцидент + операція" за docs/access-matrix.md.
// Власник і роль беруться лише з перевіреного principal (cookie) та з entity, ніколи з тіла запиту.
public sealed class IncidentAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident incident)
    {
        var userIdValue = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var isOwner = Guid.TryParse(userIdValue, out var userId) && userId == incident.OwnerUserId;
        var isAnalyst = context.User.IsInRole(DbSeeder.AnalystRole);

        var allowed = requirement.Name switch
        {
            // Власник читає свій інцидент; Analyst читає будь-який для аналізу.
            nameof(IncidentOperations.Read) => isOwner || isAnalyst,
            // Редагує й видаляє лише власник. Статус для delete перевіряє endpoint (409).
            nameof(IncidentOperations.Update) => isOwner,
            nameof(IncidentOperations.Delete) => isOwner,
            // Triage — лише Analyst. Статус New перевіряє endpoint (409).
            nameof(IncidentOperations.Triage) => isAnalyst,
            _ => false
        };

        if (allowed)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
