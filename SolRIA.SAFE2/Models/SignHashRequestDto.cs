namespace SolRIA.SAFE.Models;

public sealed class SignHashRequestDto
{
    [Newtonsoft.Json.JsonProperty("sad")]
    public string Sad { get; set; }

    [Newtonsoft.Json.JsonProperty("hashes")]
    public ICollection<string> Hashes { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [Newtonsoft.Json.JsonProperty("signAlgo")]
    //[System.ComponentModel.DataAnnotations.RegularExpression(@"1.2.840.113549.1.1.11")]
    public string SignAlgo { get; set; }

    [Newtonsoft.Json.JsonProperty("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();

    [Newtonsoft.Json.JsonProperty("credentialID")]
    public string CredentialID { get; set; }
}