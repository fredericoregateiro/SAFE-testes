namespace SolRIA.Sign.SAFE.Models;

public sealed class UpdateTokenResponseDto
{
    [System.Text.Json.Serialization.JsonPropertyName("newAccessToken")]
    public string NewAccessToken { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("newRefreshToken")]
    public string NewRefreshToken { get; set; }
}