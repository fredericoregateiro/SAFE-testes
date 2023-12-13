namespace SolRIA.SAFE.Models;

public class AccountCreationResult
{
    [Newtonsoft.Json.JsonProperty("accessToken")]
    public string AccessToken { get; set; }

    [Newtonsoft.Json.JsonProperty("refreshToken")]
    public string RefreshToken { get; set; }

    [Newtonsoft.Json.JsonProperty("oauthToken")]
    public string OauthToken { get; set; }

    [Newtonsoft.Json.JsonProperty("accountExpirationDate")]
    public DateTime AccountExpirationDate { get; set; }

    [Newtonsoft.Json.JsonProperty("error")]
    public string Error { get; set; }

    [Newtonsoft.Json.JsonProperty("error_description")]
    public string ErrorDescription { get; set; }
}
