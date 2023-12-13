namespace SolRIA.SAFE.Models;

public sealed class KeyInformationDto
{
    [Newtonsoft.Json.JsonProperty("status")]
    public string Status { get; set; }

    [Newtonsoft.Json.JsonProperty("algo")]
    public string Algo { get; set; }

    [Newtonsoft.Json.JsonProperty("len")]
    public string Len { get; set; }
}