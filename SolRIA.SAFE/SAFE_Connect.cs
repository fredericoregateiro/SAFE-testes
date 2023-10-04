using System.Net;
using System.Text;
using System.Text.Json;
using SolRIA.Sign.SAFE;
using SolRIA.Sign.SAFE.Models;

namespace SAFE;

public class SAFE_Connect
{
    private readonly string baseURL = "https://pprsafe.autenticacao.gov.pt";

    private readonly string username = "clientTest";
    private readonly string password = "Test";

    private readonly string SAFE_AccessToken = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\AccessTokenTeste.txt";
    private readonly string SAFE_RefreshToken = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\RefreshTokenTeste.txt";

    public void UpdateAccessToken(string newToken)
    {
        //TODO: save the token in the condiguration
        File.WriteAllText(SAFE_AccessToken, newToken);
    }
    public void UpdateRefreshToken(string newToken)
    {
        //TODO: save the token in the condiguration
        File.WriteAllText(SAFE_RefreshToken, newToken);
    }

    private JsonSerializerOptions serializerOptions;

    /// <summary>
    /// Método que retorna um novo AccessToken e um novo RefreshToken para uma conta de assinatura. 
    /// Estes novos tokens devem ser utilizados nas invocações futuras aos serviços. 
    /// Este método deve ser invocado sempre que o sistema retorne o erro HTTP 400 Bad Request, 
    /// com a mensagem de erro “The access or refresh token is expired or has been revoked”
    /// </summary>
    public async Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, HttpClient httpClient)
    {
        return await UpdateToken(body, httpClient, CancellationToken.None);
    }
    public async Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/signatureAccount/updateToken");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationRefreshHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<UpdateTokenResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    public static void CreateAccount()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "http://interop.gov.pt/SAFE/createSignatureAccount");
    }

    /// <summary>
    /// Método que permite o cancelamento de uma conta de assinatura.
    /// </summary>
    public async Task<string> CancelAccount(CancelCitizenAccountRequestDto body, HttpClient httpClient)
    {
        return await CancelAccount(body, httpClient, CancellationToken.None);
    }
    public async Task<string> CancelAccount(CancelCitizenAccountRequestDto body, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/signatureAccount/cancel");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        //valid response
        if (response.StatusCode == HttpStatusCode.OK) return string.Empty;

        // error responses
        if (response.StatusCode == HttpStatusCode.Unauthorized) return "Unauthorized";
        if (response.StatusCode == HttpStatusCode.BadRequest) return "Bad Request";
        if (response.StatusCode == HttpStatusCode.InternalServerError) return "Internal Server Error";

        return "Invalid response";
    }

    /// <summary>
    /// Método que retorna informação sobre o serviço e a lista de todos os métodos implementados.
    /// </summary>
    public async Task<InfoResponseDto> Info(HttpClient httpClient)
    {
        return await Info(httpClient, CancellationToken.None);
    }
    public async Task<InfoResponseDto> Info(HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/info");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<InfoResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que retorna a lista de credenciais associados a uma conta de assinatura. 
    /// Cada conta de assinatura do SAFE tem apenas uma credencial, 
    /// que deve ser enviada em todos os métodos que requeiram o parâmetro credentialId
    /// </summary>
    public async Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, HttpClient httpClient)
    {
        return await ListCredential(body, httpClient, CancellationToken.None);
    }
    public async Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/credentials/list");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<CredentialsListResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que retorna a informação associada a uma conta de assinatura. 
    /// Nomeadamente, informação sobre o estado da conta de assinatura e a 
    /// cadeia de certificados associados à conta de assinatura. 
    /// A cadeia de certificados deve ser utilizada para construir os documentos assinados 
    /// associadas à conta de assinatura.
    /// </summary>
    public async Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, HttpClient httpClient)
    {
        return await InfoCredentials(body, httpClient, CancellationToken.None);
    }
    public async Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/credentials/info");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<CredentialsInfoResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que pede autorização para efetuar uma assinatura. 
    /// Neste método, o Software de Faturação deve gerar a(s) hash(es) do(s) documento(s) a assinar, 
    /// o SAFE regista a(s) hash(es) a assinar e gera um Signature Activation Data (SAD)
    /// que terá de ser enviado pelo Software de Faturação no pedido de assinatura <see cref="SignHash"/>. 
    /// Um SAD é único para cada pedido assinatura.
    /// </summary>
    public async Task<string> Authorize(SignHashAuthorizationRequestDto body, HttpClient httpClient)
    {
        return await Authorize(body, httpClient, CancellationToken.None);
    }
    public async Task<string> Authorize(SignHashAuthorizationRequestDto body, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/v2/credentials/authorize");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        //valid response
        if (response.StatusCode == HttpStatusCode.OK) return string.Empty;

        // error responses
        // read the request headers
        var headers = ReadHeaders(response);

        var responseData = response.Content == null ? null : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        throw new ApiException("The HTTP status code of the response was not expected (" + (int)response.StatusCode + ").", response.StatusCode, responseData, headers, null);
        // if (response.StatusCode == HttpStatusCode.Unauthorized) return "Unauthorized";
        // if (response.StatusCode == HttpStatusCode.BadRequest) return "Bad Request";
        // if (response.StatusCode == HttpStatusCode.InternalServerError) return "Internal Server Error";

        // return "Invalid response";
    }

    /// <summary>
    /// Método que verifica autorização para efetuar uma assinatura.
    /// Neste método, o Software de Faturação deve enviar o processId utilizado na invocação do método
    /// de pedido de autorização <see cref="Authorize"/>. 
    /// O SAFE devolve o Signature Activation Data (SAD) que terá de ser enviado pelo Software
    /// de Faturação no pedido de assinatura <see cref="SignHash"/>.
    /// Um SAD é único para cada pedido assinatura. 
    /// Este método deve ser invocado do seguinte modo: 
    /// A primeira invocação deve ser feita 1 segundo após a invocação do método de pedido de autorização <see cref="Authorize"/>.
    /// Se o SAFE devolver um código HTTP 204 No Content (ou seja, não devolver o SAD), 
    /// o pedido deve ser repetido mais 4 vezes (total de 5 vezes), com intervalos de 1 segundo.
    /// </summary>
    public async Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, HttpClient httpClient)
    {
        return await VerifyAuth(processId, httpClient, CancellationToken.None);
    }
    public async Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseURL}/credentials/authorize/verify?processId=" + Uri.UnescapeDataString(processId));
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<SignHashAuthorizationResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que pede assinatura de hash(es). 
    /// Este método que deve ser invocado após a invocação do método de verificação de autorização <see cref="VerifyAuth"/>,
    /// verifica se o SAD recebido corresponde ao que foi gerado no método de autorização, e assina a(s) hash(es) assinada(s).
    /// </summary>
    public async Task<string> SignHash(SignHashRequestDto body, HttpClient httpClient)
    {
        return await SignHash(body, httpClient, CancellationToken.None);
    }
    public async Task<string> SignHash(SignHashRequestDto body, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseURL}/v2/signatures/signHash");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        //valid response
        if (response.StatusCode == HttpStatusCode.OK) return string.Empty;

        // error responses
        // read the request headers
        var headers = ReadHeaders(response);

        var responseData = response.Content == null ? null : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        throw new ApiException("The HTTP status code of the response was not expected (" + (int)response.StatusCode + ").", response.StatusCode, responseData, headers, null);
        // if (response.StatusCode == HttpStatusCode.Unauthorized) return "Unauthorized";
        // if (response.StatusCode == HttpStatusCode.BadRequest) return "Bad Request";
        // if (response.StatusCode == HttpStatusCode.InternalServerError) return "Internal Server Error";

        // return "Invalid response";
    }

    /// <summary>
    /// Método que retorna a(s) hash(es) assinada(s). 
    /// Este método deve ser invocado após a invocação do método de pedido de assinatura autorização
    /// <see cref="SignHash"/>.
    /// O Software de Faturação deve enviar o processId utilizado na invocação do método de pedido de assinatura
    /// <see cref="SignHash"/> e o SAFE verifica se a assinatura já foi efetuada. 
    /// Se sim, o SAFE devolve a(s) hash(es) assinada(s). 
    /// Neste passo, o Software de Faturação deve construir o documento assinado, juntando, ao documento original, 
    /// a hash assinada do documento e os certificados obtidos no método credentials/info <see cref="Info"/>. 
    /// Este método deve ser invocado do seguinte modo: 
    /// a primeira invocação deve ser feita 1 segundo após a invocação do método de pedido de assinatura <see cref="SignHash"/>.
    /// Se o SAFE devolver um código HTTP 204 No Content (ou seja, não devolver a(s) hash(es) assinada(s)) 
    /// o pedido deve ser repetido mais 4 vezes (num total de 5 vezes), com intervalos de 1 segundo.
    /// </summary>
    public async Task<SignHashResponseDto> VerifyHash(string processId, HttpClient httpClient)
    {
        return await VerifyHash(processId, httpClient, CancellationToken.None);
    }
    public async Task<SignHashResponseDto> VerifyHash(string processId, HttpClient httpClient, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseURL}/signatures/signHash/verify?processId=" + Uri.UnescapeDataString(processId));
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);

        var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<SignHashResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    private void AddAuthenticationHeaders(HttpRequestMessage request)
    {
        //TODO: get token from db config
        string token = File.ReadAllText(SAFE_AccessToken);

        AddAuthenticationHeaders(request, token);
    }
    private void AddAuthenticationRefreshHeaders(HttpRequestMessage request)
    {
        //TODO: get token from db config
        string token = File.ReadAllText(SAFE_RefreshToken);

        AddAuthenticationHeaders(request, token);
    }
    private void AddAuthenticationHeaders(HttpRequestMessage request, string token)
    {
        request.Headers.TryAddWithoutValidation("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));
        request.Headers.TryAddWithoutValidation("SAFEAuthorization", $"Bearer {token}");
    }

    private void AddJsonBodyToRequest<T>(T body, HttpRequestMessage request)
    {
        var json = JsonSerializer.Serialize(body, serializerOptions);
        var content = new StringContent(json);
        content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
        request.Content = content;
    }

    private async Task<ObjectResponseResult<T>> ReadObjectResponseAsync<T>(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response == null || response.Content == null)
        {
            return new ObjectResponseResult<T>(default, string.Empty);
        }

        if (response.StatusCode != HttpStatusCode.OK)
        {
            // read the request headers
            var headers = ReadHeaders(response);

            var responseData = response.Content == null ? null : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            throw new ApiException("The HTTP status code of the response was not expected (" + (int)response.StatusCode + ").", response.StatusCode, responseData, headers, null);
        }

        var responseText = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            serializerOptions ??= new JsonSerializerOptions
            {
                Converters =
                {
                    new DateTimeFormat()
                }
            };
            var typedBody = JsonSerializer.Deserialize<T>(responseText, serializerOptions);
            return new ObjectResponseResult<T>(typedBody, responseText);
        }
        catch (JsonException exception)
        {
            // read the request headers
            var headers = ReadHeaders(response);

            var message = "Could not deserialize the response body string as " + typeof(T).FullName + ".";
            throw new ApiException(message, response.StatusCode, responseText, headers, exception);
        }
    }

    private static Dictionary<string, IEnumerable<string>> ReadHeaders(HttpResponseMessage response)
    {
        var headers = Enumerable.ToDictionary(response.Headers, h => h.Key, h => h.Value);
        if (response.Content != null && response.Content.Headers != null)
        {
            foreach (var item_ in response.Content.Headers)
                headers[item_.Key] = item_.Value;
        }

        return headers;
    }

    private static void GuardResultNotNull<T>(HttpResponseMessage response, ObjectResponseResult<T> objectResponse)
    {
        if (objectResponse.Object != null) return;

        // read the request headers
        var headers = ReadHeaders(response);

        throw new ApiException("Response was null which was not expected.", response.StatusCode, objectResponse.Text, headers, null);
    }
}