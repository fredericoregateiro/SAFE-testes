namespace SolRIA.SAFE.Models;

public sealed class UpdateTokenRequestDto
{
    [Newtonsoft.Json.JsonProperty("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();

    [Newtonsoft.Json.JsonProperty("credentialID")]
    public string CredentialID { get; set; }
}