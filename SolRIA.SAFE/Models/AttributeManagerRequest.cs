namespace SolRIA.SAFE.Models;

public class AttributeManagerRequest
{
    [System.Text.Json.Serialization.JsonPropertyName("token")]
    public string Token { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("attributesName")]
    public string[] AttributesName { get; set; }
}
