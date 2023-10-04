using System.Text.Json.Serialization;

namespace SolRIA.Sign.SAFE.Models;

public class ErrorResultDto
{
    [JsonPropertyName("error")]
    public string Error { get; set; }

    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; }
}