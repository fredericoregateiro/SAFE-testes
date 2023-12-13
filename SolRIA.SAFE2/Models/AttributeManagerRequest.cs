namespace SolRIA.SAFE.Models;

public class AttributeManagerRequest
{
    [Newtonsoft.Json.JsonProperty("token")]
    public string Token { get; set; }

    [Newtonsoft.Json.JsonProperty("attributesName")]
    public string[] AttributesName { get; set; }
}
