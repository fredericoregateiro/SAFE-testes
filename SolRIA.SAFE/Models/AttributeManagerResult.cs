namespace SolRIA.SAFE.Models;

public class AttributeManagerResult
{
    [System.Text.Json.Serialization.JsonPropertyName("token")]
    public string Token { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("authenticationContextId")]
    public string AuthenticationContextId { get; set; }
}
