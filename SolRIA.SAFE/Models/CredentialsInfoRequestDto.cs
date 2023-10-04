namespace SolRIA.Sign.SAFE.Models;

public sealed class CredentialsInfoRequestDto
{
    [System.Text.Json.Serialization.JsonPropertyName("credentialID")]
    public string CredentialID { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("certificates")]
    [System.ComponentModel.DataAnnotations.RegularExpression(@"none|single|chain")]
    public string Certificates { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();
}