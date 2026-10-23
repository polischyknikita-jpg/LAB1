namespace SecureLab.Api.Presentation.Contracts;

// ЛР 04: звичайне редагування змінює лише content fields.
// OwnerUserId, Status, Severity, Role тут немає — невідомі поля JSON ігноруються.
public sealed record UpdateIncidentRequest(string? Title, string? Description);

public sealed record IncidentUpdatedResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset UpdatedAtUtc);

public sealed record IncidentTriageResponse(Guid Id, string Status);
