namespace FormulaOneApp.Models.DTOs;

public class TokenRequest
{
    public string Token { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
}
