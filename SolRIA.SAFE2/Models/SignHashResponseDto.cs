namespace SolRIA.SAFE.Models;

public sealed class SignHashResponseDto
{
    [Newtonsoft.Json.JsonProperty("signatures")]
    public ICollection<string> Signatures { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}