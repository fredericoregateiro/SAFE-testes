namespace SolRIA.Sign.SAFE.Models;

public sealed class CredentialsInfoResponseDto
{
    [System.Text.Json.Serialization.JsonPropertyName("key")]
    public KeyInformationDto Key { get; set; } = new KeyInformationDto();

    [System.Text.Json.Serialization.JsonPropertyName("cert")]
    public CertificateInformationDto Cert { get; set; } = new CertificateInformationDto();

    [System.Text.Json.Serialization.JsonPropertyName("authMode")]
    public string AuthMode { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("multisign")]
    public int Multisign { get; set; }
}