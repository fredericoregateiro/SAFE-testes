namespace SolRIA.SAFE.Models;

public class AttributeResult
{
    [System.Text.Json.Serialization.JsonPropertyName("name")]
    public string Name { get; set; }
    [System.Text.Json.Serialization.JsonPropertyName("value")]
    public string Value { get; set; }
    [System.Text.Json.Serialization.JsonPropertyName("state")]
    public string State { get; set; }
}
