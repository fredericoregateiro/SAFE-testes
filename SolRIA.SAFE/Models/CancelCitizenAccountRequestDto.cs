namespace SolRIA.Sign.SAFE.Models;

public sealed class CancelCitizenAccountRequestDto
{
    [System.Text.Json.Serialization.JsonPropertyName("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();

    [System.Text.Json.Serialization.JsonPropertyName("credentialID")]
    public string CredentialID { get; set; }
}