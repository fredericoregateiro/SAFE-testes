namespace SolRIA.SAFE.Models;

public sealed class CredentialsListRequestDto
{
    [Newtonsoft.Json.JsonProperty("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();
}