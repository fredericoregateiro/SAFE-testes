namespace SolRIA.Sign.SAFE.Models;

public sealed class SignHashRequestDto
{
    [System.Text.Json.Serialization.JsonPropertyName("sad")]
    public string Sad { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("hashes")]
    public ICollection<string> Hashes { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [System.Text.Json.Serialization.JsonPropertyName("signAlgo")]
    [System.ComponentModel.DataAnnotations.RegularExpression(@"1.2.840.113549.1.1.11")]
    public string SignAlgo { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("clientData")]
    public ClientDataRequestBaseDto ClientData { get; set; } = new ClientDataRequestBaseDto();

    [System.Text.Json.Serialization.JsonPropertyName("credentialID")]
    public string CredentialID { get; set; }
}