namespace SolRIA.Sign.SAFE.Models;

public sealed class SignHashAuthorizationRequestDto
{
    [System.Text.Json.Serialization.JsonPropertyName("numSignatures")]
    public int NumSignatures { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("hashes")]
    public ICollection<string> Hashes { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [System.Text.Json.Serialization.JsonPropertyName("clientData")]
    public SignHashAuthorizationClientDataRequestDto ClientData { get; set; } = new SignHashAuthorizationClientDataRequestDto();

    [System.Text.Json.Serialization.JsonPropertyName("credentialID")]
    public string CredentialID { get; set; }
}