namespace VulnerableIssuerAPI.Models.DTOs
{
    public record ErrorResponse
    (
        string Error,
        string ErrorId,
        string? Code = null
    );
    
}
