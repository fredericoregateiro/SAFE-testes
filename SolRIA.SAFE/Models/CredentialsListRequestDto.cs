namespace SolRIA.Sign.SAFE.Models;

public sealed class CredentialsListRequestDto
{
    [System.Text.Json.Serialization.JsonPropertyName("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();
}