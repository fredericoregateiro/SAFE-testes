namespace SolRIA.SAFE.Models;

public sealed class UpdateTokenResponseDto
{
    [Newtonsoft.Json.JsonProperty("newAccessToken")]
    public string NewAccessToken { get; set; }

    [Newtonsoft.Json.JsonProperty("newRefreshToken")]
    public string NewRefreshToken { get; set; }
}