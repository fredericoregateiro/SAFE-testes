namespace SolRIA.Sign.SAFE.Models;

public sealed class SignHashResponseDto
{
    [System.Text.Json.Serialization.JsonPropertyName("signatures")]
    public ICollection<string> Signatures { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}