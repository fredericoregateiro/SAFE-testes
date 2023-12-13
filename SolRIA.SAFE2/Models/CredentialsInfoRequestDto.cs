namespace SolRIA.SAFE.Models;

public sealed class CredentialsInfoRequestDto
{
    [Newtonsoft.Json.JsonProperty("credentialID")]
    public string CredentialID { get; set; }

    [Newtonsoft.Json.JsonProperty("certificates")]
    //[System.ComponentModel.DataAnnotations.RegularExpression(@"none|single|chain")]
    public string Certificates { get; set; }

    [Newtonsoft.Json.JsonProperty("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();
}