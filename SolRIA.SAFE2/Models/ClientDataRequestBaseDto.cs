namespace SolRIA.SAFE.Models;

public sealed class ClientDataRequestBaseDto
{
    [Newtonsoft.Json.JsonProperty("processId")]
    public string ProcessId { get; set; }

    [Newtonsoft.Json.JsonProperty("clientName")]
    public string ClientName { get; set; }
}