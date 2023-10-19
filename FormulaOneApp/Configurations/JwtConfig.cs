namespace FormulaOneApp.Configurations;

public class JwtConfig
{
    public string Secret { get; set; } = null!;
    public TimeSpan ExpiryTimeFrame { get; set; }
}