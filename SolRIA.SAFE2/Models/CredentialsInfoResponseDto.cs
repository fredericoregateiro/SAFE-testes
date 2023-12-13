namespace SolRIA.SAFE.Models;

public sealed class CredentialsInfoResponseDto
{
    [Newtonsoft.Json.JsonProperty("key")]
    public KeyInformationDto Key { get; set; } = new KeyInformationDto();

    [Newtonsoft.Json.JsonProperty("cert")]
    public CertificateInformationDto Cert { get; set; } = new CertificateInformationDto();

    [Newtonsoft.Json.JsonProperty("authMode")]
    public string AuthMode { get; set; }

    [Newtonsoft.Json.JsonProperty("multisign")]
    public int Multisign { get; set; }
}