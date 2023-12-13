namespace SolRIA.SAFE.Models;

public class AccountCreationResult
{
    [System.Text.Json.Serialization.JsonPropertyName("accessToken")]
    public string AccessToken { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("refreshToken")]
    public string RefreshToken { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("oauthToken")]
    public string OauthToken { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("accountExpirationDate")]
    public DateTime AccountExpirationDate { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("error")]
    public string Error { get; set; }

    [System.Text.Json.Serialization.JsonPropertyName("error_description")]
    public string ErrorDescription { get; set; }
}
