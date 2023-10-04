namespace SolRIA.Sign.SAFE.Models;

public sealed class SignHashAuthorizationClientDataRequestDto
{
    [System.Text.Json.Serialization.JsonPropertyName("processId")]
    public string ProcessId { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("documentNames")]
    public ICollection<string> DocumentNames { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [System.Text.Json.Serialization.JsonPropertyName("clientName")]
    public string ClientName { get; set; }
}