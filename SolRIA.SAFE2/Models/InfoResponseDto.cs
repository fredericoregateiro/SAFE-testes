namespace SolRIA.SAFE.Models;

public sealed class InfoResponseDto
{
    [Newtonsoft.Json.JsonProperty("specs")]
    public string Specs { get; set; }

    [Newtonsoft.Json.JsonProperty("name")]
    public string Name { get; set; }

    [Newtonsoft.Json.JsonProperty("logo")]
    public string Logo { get; set; }

    [Newtonsoft.Json.JsonProperty("region")]
    public string Region { get; set; }

    [Newtonsoft.Json.JsonProperty("lang")]
    public string Lang { get; set; }

    [Newtonsoft.Json.JsonProperty("description")]
    public string Description { get; set; }

    [Newtonsoft.Json.JsonProperty("authType")]
    public ICollection<string> AuthType { get; set; } = new System.Collections.ObjectModel.Collection<string>();

    [Newtonsoft.Json.JsonProperty("methods")]
    public ICollection<string> Methods { get; set; } = new System.Collections.ObjectModel.Collection<string>();
}