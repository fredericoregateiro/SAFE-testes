namespace SolRIA.SAFE.Models;

public class AttributeResult
{
    [Newtonsoft.Json.JsonProperty("name")]
    public string Name { get; set; }
    [Newtonsoft.Json.JsonProperty("value")]
    public string Value { get; set; }
    [Newtonsoft.Json.JsonProperty("state")]
    public string State { get; set; }
}
