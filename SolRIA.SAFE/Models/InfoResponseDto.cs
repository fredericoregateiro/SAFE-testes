namespace SolRIA.Sign.SAFE.Models;

public sealed class InfoResponseDto
{
    [System.Text.Json.Serialization.JsonPropertyName("specs")]
    public string Specs { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("name")]
    public string Name { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("logo")]
    public string Logo { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("region")]
    public string Region { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("lang")]
    public string Lang { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("description")]
    public string Description { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("authType")]
    public ICollection<string> AuthType { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [System.Text.Json.Serialization.JsonPropertyName("methods")]
    public ICollection<string> Methods { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}