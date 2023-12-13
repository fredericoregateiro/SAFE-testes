namespace SolRIA.SAFE.Models;

public sealed class Config
{
    public int Id { get; set; }
    public string CredentialID { get; set; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }

    public string AccountExpirationDate { get; set; }
    public string UpdatedAt { get; set; }

    public string CertStatus { get; set; }
    public string CertAlgo { get; set; }
    public string CertLen { get; set; }
}