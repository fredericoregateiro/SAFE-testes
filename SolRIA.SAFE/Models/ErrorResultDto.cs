namespace SolRIA.Sign.SAFE.Models;

public class ErrorResultDto
{
    [System.Text.Json.Serialization.JsonPropertyName("error")]
    public string Error { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; }
}