namespace SolRIA.Sign.SAFE.Models;

public sealed class ClientDataRequestBaseDto
{
    [System.Text.Json.Serialization.JsonPropertyName("processId")]
    public string ProcessId { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("clientName")]
    public string ClientName { get; set; }
}