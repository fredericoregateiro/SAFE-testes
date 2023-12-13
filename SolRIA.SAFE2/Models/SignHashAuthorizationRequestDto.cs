namespace SolRIA.SAFE.Models;

public sealed class SignHashAuthorizationRequestDto
{
    [Newtonsoft.Json.JsonProperty("numSignatures")]
    public int NumSignatures { get; set; }

    [Newtonsoft.Json.JsonProperty("hashes")]
    public ICollection<string> Hashes { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [Newtonsoft.Json.JsonProperty("clientData")]
    public SignHashAuthorizationClientDataRequestDto ClientData { get; set; } = new SignHashAuthorizationClientDataRequestDto();

    [Newtonsoft.Json.JsonProperty("credentialID")]
    public string CredentialID { get; set; }
}