namespace SolRIA.SAFE.Models;

public sealed class CredentialsListResponseDto
{
    [Newtonsoft.Json.JsonProperty("credentialIDs")]
    public ICollection<string> CredentialIDs { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}