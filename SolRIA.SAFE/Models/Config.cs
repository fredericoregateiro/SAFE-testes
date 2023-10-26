namespace SolRIA.Sign.SAFE.Models;

public sealed class Config
{
    public int Id { get; set; }
    public string CredentialID { get; set; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
}