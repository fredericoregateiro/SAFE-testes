namespace SolRIA.SAFE.Models;

public class ErrorResultDto
{
    [Newtonsoft.Json.JsonProperty("error")]
    public string Error { get; set; }

    [Newtonsoft.Json.JsonProperty("error_description")]
    public string ErrorDescription { get; set; }
}