namespace SolRIA.SAFE.Models;

public sealed class SignHashAuthorizationClientDataRequestDto
{
    [Newtonsoft.Json.JsonProperty("processId")]
    public string ProcessId { get; set; }

    [Newtonsoft.Json.JsonProperty("documentNames")]
    public ICollection<string> DocumentNames { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [Newtonsoft.Json.JsonProperty("clientName")]
    public string ClientName { get; set; }
}