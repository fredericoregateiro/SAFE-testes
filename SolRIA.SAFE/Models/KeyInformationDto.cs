namespace SolRIA.Sign.SAFE.Models;

public sealed class KeyInformationDto
{
    [System.Text.Json.Serialization.JsonPropertyName("status")]
    public string Status { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("algo")]
    public string Algo { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("len")]
    public string Len { get; set; }
}