namespace SolRIA.Sign.SAFE.Models;

public sealed class CredentialsListResponseDto
{
    [System.Text.Json.Serialization.JsonPropertyName("credentialIDs")]
    public ICollection<string> CredentialIDs { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}