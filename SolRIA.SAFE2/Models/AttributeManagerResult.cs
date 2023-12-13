namespace SolRIA.SAFE.Models;

public class AttributeManagerResult
{
    [Newtonsoft.Json.JsonProperty("token")]
    public string Token { get; set; }

    [Newtonsoft.Json.JsonProperty("authenticationContextId")]
    public string AuthenticationContextId { get; set; }
}
