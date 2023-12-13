using Newtonsoft.Json;
using SolRIA.SAFE.Interfaces;
using SolRIA.SAFE.Models;
using SolRIA.SAFE2;
using Syncfusion.Pdf.Graphics;
using Syncfusion.Pdf.Parsing;
using Syncfusion.Pdf.Security;
using System.Drawing;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;

namespace SAFE;

/// <summary>
/// Classe com vários métodos de acesso ao serviço SAFE
/// </summary>
public class SAFE_Connect : ISAFE_Connect
{
    private BasicAuth _auth;

    private readonly HttpClient _httpClient;
    private readonly HttpClient _httpClientOauth;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="httpClient">Cliente http para aceder a API de assinatura dos documentos do serviço SAFE</param>
    /// <param name="httpClientOauth">Cliente http para aceder a API de autenticação do serviço AMA</param>
    public SAFE_Connect(HttpClient httpClient, HttpClient httpClientOauth)
    {
        _httpClient = httpClient;
        _httpClientOauth = httpClientOauth;

        serializerOptions = new JsonSerializerSettings() { DateFormatString = "yyyy-MM-dd HH:mm:ss" };
    }

    /// <summary>
    /// Inicializa as credenciais da SW fornecidas pelo SAFE
    /// </summary>
    /// <param name="auth">Credenciais</param>
    public void Init(BasicAuth auth)
    {
        _auth = auth;
    }

    private readonly JsonSerializerSettings serializerOptions;

    /// <summary>
    /// Método que retorna um novo AccessToken e um novo RefreshToken para uma conta de assinatura. 
    /// Estes novos tokens devem ser utilizados nas invocações futuras aos serviços. 
    /// Este método deve ser invocado sempre que o sistema retorne o erro HTTP 400 Bad Request, 
    /// com a mensagem de erro “The access or refresh token is expired or has been revoked”
    /// </summary>
    public async Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, Config config)
    {
        return await UpdateToken(body, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrona do método <see cref="UpdateToken(UpdateTokenRequestDto, Config)"/>
    /// </summary>
    public async Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/signatureAccount/updateToken");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationRefreshHeaders(request, config);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<UpdateTokenResponseDto>(response).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que gera o url que será usado no pedido oauth
    /// </summary>
    /// <param name="creationRequest">Parametros usados na criação da conta do cliente</param>
    /// <param name="redirectUri">Endereço invocado pelo serviço SAFE com as credenciais ou mensagem de erro</param>
    /// <returns>Url usado no pedido de autenticação oauth</returns>
    public string CreateAccountUrl(AccountCreationRequest creationRequest, string redirectUri)
    {
        // check the valid date
        if (string.IsNullOrWhiteSpace(creationRequest.Valid))
            creationRequest.Valid = AccountCreationRequest.FillValid();

        if (string.IsNullOrWhiteSpace(creationRequest.Info) == false)
            creationRequest.Info = Uri.EscapeDataString(creationRequest.Info);

        var createAccountParams = $"?enterpriseNipc={creationRequest.NIF}$enterpriseAdditionalInfo={creationRequest.Info}$email={creationRequest.Email}$expirationDate={creationRequest.Valid}$signaturesLimit={creationRequest.Max}$creationClientName={_auth.ClientName}";

        // scopes obrigatórios para criar a conta pelo oauth
        var scopesList = new string[]
        {
            "http://interop.gov.pt/MDC/Cidadao/NIC",
            "http://interop.gov.pt/MDC/Cidadao/NomeProprio",
            "http://interop.gov.pt/MDC/Cidadao/NomeApelido",
            "http://interop.gov.pt/MDC/Cidadao/DataNascimento",
            "http://interop.gov.pt/MDC/Cidadao/NIF",
            $"http://interop.gov.pt/SAFE/createSignatureAccount{createAccountParams}",
        };

        // criar url com todos os scopes necessários separados por espaço
        var scopesUrl = string.Join("%20", scopesList);
        var baseAddress = _httpClientOauth.BaseAddress.AbsoluteUri;

        return $"{baseAddress}/oauth/askauthorization?redirect_uri={redirectUri}&client_id={_auth.ClientId}&scope={scopesUrl}&response_type=token";
    }

    /// <summary>
    /// Lê o <paramref name="url"/> enviado pelo serviço SAFE e verifica a existência de erros e caso existam lê as credenciais
    /// </summary>
    /// <param name="url">Url de retorno criado pelo serviço SAFE com as credenciais pedidas ou mensagem de erro</param>
    /// <returns></returns>
    public MessageResult ParseOauthResult(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;

        //obter a url a partir do authorized#
        var parameterStartIndex = url.IndexOf("/authorized#", StringComparison.OrdinalIgnoreCase);

        if (parameterStartIndex < 0) return null;

        var queryString = url.Substring(parameterStartIndex + 12);

        var queryParameters = HttpUtility.ParseQueryString(queryString);

        // parse the url

        /* Sucesso
         * https://preprod.autenticacao.gov.pt/OAuth/Authorized#
         * access_token=
         * &token_type=bearer
         * &expires_in=
         * &state=
         * &refresh_token=
         */

        /*
         * Erro
         * https://preprod.autenticacao.gov.pt/oauth/authorized#error=XXXXX 
         * XXXXX = invalid_request: quando é um pedido inválido por exemplo com campos obrigatórios vazios
         * XXXXX = unauthorized_client: quando o id do cliente é inválido
         * XXXXX = unsupported_grant_type: quando o grant_type passado não equivale a token
         * XXXXX = cancelled: quando o utilizador cancela o login
         */

        // verificar existencia de erros
        string error = queryParameters["error"];
        if (string.IsNullOrWhiteSpace(error) == false)
        {
            return new MessageResult { Success = false, Message = queryParameters["error"] };
        }

        return new MessageResult { Success = true, Message = queryParameters["access_token"] };
    }

    /// <summary>
    /// Método que envia o pedido de criação de conta para assinatura da FA
    /// </summary>
    /// <param name="token">access_token enviado pela autenticação oauth</param>
    /// <returns>Credenciais de autenticação usados no pedido de leitura da conta <see cref="ReadAccount(AttributeManagerResult)"/> </returns>
    public async Task<AttributeManagerResult> SendCreateAccountRequest(string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            "/oauthresourceserver/api/AttributeManager");
        request.Headers.TryAddWithoutValidation("accept", "*/*");

        var dto = new AttributeManagerRequest
        {
            Token = token,
            AttributesName = new string[] { "http://interop.gov.pt/SAFE/createSignatureAccount" },
        };

        var content = new StringContent(JsonConvert.SerializeObject(dto));
        content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
        request.Content = content;

        var result = await _httpClientOauth.SendAsync(request).ConfigureAwait(false);

        var resultJson = await result.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonConvert.DeserializeObject<AttributeManagerResult>(resultJson);
    }

    /// <summary>
    /// Método que envia o pedido de credenciais da conta criada pelo oauth
    /// </summary>
    /// <param name="attribute">Tokens de autenticação recebidos no pedido de criação de conta <see cref="SendCreateAccountRequest(string)"/></param>
    /// <returns>Tokens de autenticação no serviço de assinatura</returns>
    public async Task<AccountCreationResult> ReadAccount(AttributeManagerResult attribute)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"/oauthresourceserver/api/AttributeManager?token={attribute.Token}&authenticationContextId={attribute.AuthenticationContextId}");
        request.Headers.TryAddWithoutValidation("accept", "*/*");

        var result = await _httpClientOauth.SendAsync(request).ConfigureAwait(false);

        var resultJson = await result.Content.ReadAsStringAsync().ConfigureAwait(false);

        var attributesResult = JsonConvert.DeserializeObject<AttributeResult[]>(resultJson);

        var attr = attributesResult.FirstOrDefault(a => a.Name.StartsWith("http://interop.gov.pt/SAFE/createSignatureAccount", StringComparison.OrdinalIgnoreCase));

        return JsonConvert.DeserializeObject<AccountCreationResult>(attr.Value);
    }

    /// <summary>
    /// Método que permite o cancelamento de uma conta de assinatura.
    /// </summary>
    public async Task<string> CancelAccount(CancelCitizenAccountRequestDto body, Config config)
    {
        return await CancelAccount(body, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrona do método <see cref="CancelAccount(CancelCitizenAccountRequestDto, Config)"/>
    /// </summary>
    public async Task<string> CancelAccount(CancelCitizenAccountRequestDto body, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/signatureAccount/cancel");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        //valid response
        if (response.StatusCode == HttpStatusCode.OK) return string.Empty;

        // error responses
        if (response.StatusCode == HttpStatusCode.Unauthorized) return "Unauthorized";

        return await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// Método que retorna informação sobre o serviço e a lista de todos os métodos implementados.
    /// </summary>
    public async Task<InfoResponseDto> Info(Config config)
    {
        return await Info(config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrona do método <see cref="Info(Config)"/>
    /// </summary>
    public async Task<InfoResponseDto> Info(Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/info");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<InfoResponseDto>(response).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que retorna a lista de credenciais associados a uma conta de assinatura. 
    /// Cada conta de assinatura do SAFE tem apenas uma credencial, 
    /// que deve ser enviada em todos os métodos que requeiram o parâmetro credentialId
    /// </summary>
    public async Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, Config config)
    {
        return await ListCredential(body, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrona do método <see cref="ListCredential(CredentialsListRequestDto, Config)"/>
    /// </summary>
    public async Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/credentials/list");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<CredentialsListResponseDto>(response).ConfigureAwait(false);

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
    public async Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, Config config)
    {
        return await InfoCredentials(body, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrona do método <see cref="InfoCredentials(CredentialsInfoRequestDto, Config)"/>
    /// </summary>
    public async Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/credentials/info");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<CredentialsInfoResponseDto>(response).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que pede autorização para efetuar uma assinatura. 
    /// Neste método, o Software de Faturação deve gerar a(s) hash(es) do(s) documento(s) a assinar, 
    /// o SAFE regista a(s) hash(es) a assinar e gera um Signature Activation Data (SAD)
    /// que terá de ser enviado pelo Software de Faturação no pedido de assinatura <see cref="SignHash(SignHashRequestDto, Config)"/>. 
    /// Um SAD é único para cada pedido assinatura.
    /// </summary>
    /// <returns>Mensagem de erro caso a operação não seja bem sucedida ou string vazio em caso de sucesso</returns>
    /// <exception cref="ApiException">Exceoção com os detalhes da resposta do serviço SAFE</exception>
    public async Task<string> Authorize(SignHashAuthorizationRequestDto body, Config config)
    {
        return await Authorize(body, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrona do método <see cref="Authorize(SignHashAuthorizationRequestDto, Config)"/>
    /// </summary>
    public async Task<string> Authorize(SignHashAuthorizationRequestDto body, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v2/credentials/authorize");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        //valid response
        if (response.StatusCode == HttpStatusCode.OK) return string.Empty;

        // error responses
        // read the request headers
        var headers = ReadHeaders(response);

        var responseData = response.Content == null ? null : await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        throw new ApiException($"The HTTP status code of the response was not expected ({response.StatusCode}).", response.StatusCode, responseData, headers, innerException: null);
        // if (response.StatusCode == HttpStatusCode.Unauthorized) return "Unauthorized";
        // if (response.StatusCode == HttpStatusCode.BadRequest) return "Bad Request";
        // if (response.StatusCode == HttpStatusCode.InternalServerError) return "Internal Server Error";

        // return "Invalid response";
    }

    /// <summary>
    /// Método que verifica autorização para efetuar uma assinatura.
    /// Neste método, o Software de Faturação deve enviar o processId utilizado na invocação do método
    /// de pedido de autorização <see cref="Authorize(SignHashAuthorizationRequestDto, Config)"/>. 
    /// O SAFE devolve o Signature Activation Data (SAD) que terá de ser enviado pelo Software
    /// de Faturação no pedido de assinatura <see cref="SignHash(SignHashRequestDto, Config)"/>.
    /// Um SAD é único para cada pedido assinatura. 
    /// Este método deve ser invocado do seguinte modo: 
    /// A primeira invocação deve ser feita 1 segundo após a invocação do método de pedido de autorização <see cref="Authorize(SignHashAuthorizationRequestDto, Config)"/>.
    /// Se o SAFE devolver um código HTTP 204 No Content (ou seja, não devolver o SAD), 
    /// o pedido deve ser repetido mais 4 vezes (total de 5 vezes), com intervalos de 1 segundo.
    /// </summary>
    public async Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, Config config)
    {
        return await VerifyAuth(processId, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrono do método <see cref="VerifyHash(string, Config)"/>
    /// </summary>
    public async Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/credentials/authorize/verify?processId=" + Uri.UnescapeDataString(processId));
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<SignHashAuthorizationResponseDto>(response).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que pede assinatura de hash(es). 
    /// Este método que deve ser invocado após a invocação do método de verificação de autorização <see cref="VerifyAuth(string, Config)"/>,
    /// verifica se o SAD recebido corresponde ao que foi gerado no método de autorização, e assina a(s) hash(es) assinada(s).
    /// </summary>
    public async Task<string> SignHash(SignHashRequestDto body, Config config)
    {
        return await SignHash(body, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// 
    /// </summary>
    /// <param name="body"></param>
    /// <param name="config"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    /// <exception cref="ApiException"></exception>
    public async Task<string> SignHash(SignHashRequestDto body, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v2/signatures/signHash");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        //valid response
        if (response.StatusCode == HttpStatusCode.OK) return string.Empty;

        // error responses
        // read the request headers
        var headers = ReadHeaders(response);

        var responseData = response.Content == null ? null : await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        throw new ApiException($"The HTTP status code of the response was not expected ({(int)response.StatusCode}).", response.StatusCode, responseData, headers, innerException: null);
        // if (response.StatusCode == HttpStatusCode.Unauthorized) return "Unauthorized";
        // if (response.StatusCode == HttpStatusCode.BadRequest) return "Bad Request";
        // if (response.StatusCode == HttpStatusCode.InternalServerError) return "Internal Server Error";

        // return "Invalid response";
    }

    /// <summary>
    /// Método que retorna a(s) hash(es) assinada(s). 
    /// Este método deve ser invocado após a invocação do método de pedido de assinatura autorização
    /// <see cref="SignHash(SignHashRequestDto, Config)"/>.
    /// O Software de Faturação deve enviar o processId utilizado na invocação do método de pedido de assinatura
    /// <see cref="SignHash(SignHashRequestDto, Config)"/> e o SAFE verifica se a assinatura já foi efetuada. 
    /// Se sim, o SAFE devolve a(s) hash(es) assinada(s). 
    /// Neste passo, o Software de Faturação deve construir o documento assinado, juntando, ao documento original, 
    /// a hash assinada do documento e os certificados obtidos no método credentials/info <see cref="Info(Config)"/>. 
    /// Este método deve ser invocado do seguinte modo: 
    /// a primeira invocação deve ser feita 1 segundo após a invocação do método de pedido de assinatura <see cref="SignHash(SignHashRequestDto, Config)"/>.
    /// Se o SAFE devolver um código HTTP 204 No Content (ou seja, não devolver a(s) hash(es) assinada(s)) 
    /// o pedido deve ser repetido mais 4 vezes (num total de 5 vezes), com intervalos de 1 segundo.
    /// </summary>
    public async Task<SignHashResponseDto> VerifyHash(string processId, Config config)
    {
        return await VerifyHash(processId, config, CancellationToken.None).ConfigureAwait(false);
    }
    /// <summary>
    /// Versão assíncrona do método <see cref="VerifyHash(string, Config)"/>
    /// </summary>
    public async Task<SignHashResponseDto> VerifyHash(string processId, Config config, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/signatures/signHash/verify?processId=" + Uri.UnescapeDataString(processId));
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request, config);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<SignHashResponseDto>(response).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    private void AddAuthenticationHeaders(HttpRequestMessage request, Config config)
    {
        AddAuthenticationHeaders(request, config.AccessToken);
    }
    private void AddAuthenticationRefreshHeaders(HttpRequestMessage request, Config config)
    {
        AddAuthenticationHeaders(request, config.RefreshToken);
    }
    private void AddAuthenticationHeaders(HttpRequestMessage request, string token)
    {
        request.Headers.TryAddWithoutValidation("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_auth.Username}:{_auth.Password}")));
        if (string.IsNullOrWhiteSpace(token) == false)
            request.Headers.TryAddWithoutValidation("SAFEAuthorization", $"Bearer {token}");
    }

    private void AddJsonBodyToRequest<T>(T body, HttpRequestMessage request)
    {
        var json = JsonConvert.SerializeObject(body, serializerOptions);
        var content = new StringContent(json);
        content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
        request.Content = content;
    }

    private async Task<ObjectResponseResult<T>> ReadObjectResponseAsync<T>(HttpResponseMessage response)
    {
        if (response == null || response.Content == null)
        {
            return new ObjectResponseResult<T>(default, string.Empty);
        }

        if (response.StatusCode != HttpStatusCode.OK)
        {
            // read the request headers
            var headers = ReadHeaders(response);

            var responseData = response.Content == null ? null : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            var responseMessage = $"The HTTP status code of the response was not expected ({(int)response.StatusCode}).";

            LogService.Log(responseMessage);
            LogService.Log(responseData);

            throw new ApiException(responseMessage, response.StatusCode, responseData, headers, innerException: null);
        }

        var responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        try
        {
            var typedBody = JsonConvert.DeserializeObject<T>(responseText, serializerOptions);
            return new ObjectResponseResult<T>(typedBody, responseText);
        }
        catch (JsonException exception)
        {
            // read the request headers
            var headers = ReadHeaders(response);

            var message = "Could not deserialize the response body string as " + typeof(T).FullName + ".";

            LogService.Log(message);
            LogService.Log(exception);

            throw new ApiException(message, response.StatusCode, responseText, headers, exception);
        }
    }

    private static Dictionary<string, IEnumerable<string>> ReadHeaders(HttpResponseMessage response)
    {
        var headers = Enumerable.ToDictionary(response.Headers, h => h.Key, h => h.Value, StringComparer.OrdinalIgnoreCase);
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

        throw new ApiException("Response was null which was not expected.", response.StatusCode, objectResponse.Text, headers, innerException: null);
    }

    /// <summary>
    /// Cria uma assinatura vazia no ficheiro PDF e devolve o hash resultante para a assinatura digital externa
    /// </summary>
    /// <param name="documentStream">Stream do ficheiro PDF a assinar</param>
    /// <param name="inputFileStream">Stream do ficheiro PDF que vai conter a assinatura</param>
    /// <param name="certificates">Lista com os certificados usados na assinatura digital</param>
    /// <param name="signatureConfig">A configuração da assinatura</param>
    /// <returns>Hash do documento a assinar pelo serviço externo</returns>
    public byte[] CreatePdfEmptySignature(Stream documentStream, Stream inputFileStream, IList<X509Certificate2> certificates, SignatureConfig signatureConfig)
    {
        //Load an existing PDF document.
        var loadedDocument = new PdfLoadedDocument(documentStream);

        //Creates a digital signature.
        var signatureBounds = new RectangleF(
                new PointF(signatureConfig.SignatureX, signatureConfig.SignatureY),
                new SizeF(signatureConfig.SignatureWidth, signatureConfig.SignatureHeight));

        var signature = new PdfSignature(loadedDocument, loadedDocument.Pages[0], certificate: null, "Signature")
        {
            //Sets the signature information.
            Bounds = signatureBounds,
        };

        signature.Settings.CryptographicStandard = CryptographicStandard.CADES;
        signature.Settings.DigestAlgorithm = DigestAlgorithm.SHA256;

        signature.ContactInfo = signatureConfig.ContactInfo;
        signature.LocationInfo = signatureConfig.LocationInfo;
        signature.Reason = signatureConfig.Reason;

        // set signature image 
        if (signatureConfig.SignatureImage != null)
        {
            //Sets an image for signature field
            var imageStream = new MemoryStream(signatureConfig.SignatureImage);
            var image = new PdfBitmap(imageStream);

            signature.Bounds = signatureBounds;

            //Create PDF graphics for the page
            PdfGraphics graphics = loadedDocument.Pages[0].Graphics;
            graphics.DrawImage(image, signatureBounds);
        }

        // set timestamp server
        if (string.IsNullOrWhiteSpace(signatureConfig.TimeStampServer) == false)
            signature.TimeStampServer = new TimeStampServer(new Uri(signatureConfig.TimeStampServer));

        signature.EnableLtv = signatureConfig.EnableLtv;
        if (signatureConfig.EnableLtv)
            signature.CreateLongTermValidity(certificates.ToList());

        //Create an external signer.
        var emptySignature = new SignEmpty();
        //Add public certificates.
        signature.AddExternalSigner(emptySignature, certificates.ToList(), Ocsp: null);

        loadedDocument.Save(inputFileStream);

        //Close the PDF document.
        loadedDocument.Close(completely: true);

        return emptySignature.Message;
    }

    /// <summary>
    /// Insere a hash assinada pelo serviço externo no ficheiro a assinar digitalmente
    /// </summary>
    /// <param name="signedHash">A hash assinada</param>
    /// <param name="inputFileStream">Stream do ficheiro PDF a assinar</param>
    /// <param name="outputFileStream">Stream do ficheiro PDF que vai conter a assinatura</param>
    /// <param name="certificates">Lista com os certificados usados na assinatura digital</param>
    public void CreatePdfSigned(string signedHash, Stream inputFileStream, Stream outputFileStream, IList<X509Certificate2> certificates)
    {
        //Create an external signer with a signed hash message.
        var externalSigner = new ExternalSigner(signedHash);

        string pdfPassword = string.Empty;

        // replace an empty signature.
        PdfSignature.ReplaceEmptySignature(inputFileStream, pdfPassword, outputFileStream, "Signature", externalSigner, certificates.ToList(), isEncodeSignature: true);
        outputFileStream.Position = 0;
    }

    /// <summary>
    /// Represents to sign an empty signature from the external signer.
    /// </summary>
    class SignEmpty : IPdfExternalSigner
    {
        public string HashAlgorithm { get; private set; } = "SHA256";

        public byte[] Message { get; set; }

        public byte[] Sign(byte[] message, out byte[] timeStampResponse)
        {
            Message = message;
            timeStampResponse = null;
            // return a null value to create an empty signed document.
            return null;
        }
    }

    /// <summary>
    /// Represents to replace an empty signature from an external signer.
    /// </summary>
    class ExternalSigner : IPdfExternalSigner
    {
        private readonly string signedHash;
        public ExternalSigner(string signedHash)
        {
            this.signedHash = signedHash;
        }
        public string HashAlgorithm { get; private set; } = "SHA256";

        public byte[] Sign(byte[] message, out byte[] timeStampResponse)
        {
            timeStampResponse = null;
            return Convert.FromBase64String(signedHash);
        }
    }

    /// <summary>
    /// Converte a hash para o formato requerido pelo SAFE
    /// </summary>
    /// <param name="message"></param>
    /// <returns></returns>
    public string CalculateHash(byte[] message)
    {
        // documento "AMA - SAFE Documento de integração.pdf" secção 6 "Geração de hashes"
        // "A hash enviada para assinatura deve ser a concatenação do sha256SigPrefix com a hash do documento"
        byte[] sha256SigPrefix = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

#if NET7_0_OR_GREATER
        message = SHA256.HashData(message);
#else
        using var ms = new MemoryStream(message);
        using var SHA256 = System.Security.Cryptography.SHA256.Create();
        message = SHA256.ComputeHash(ms);
#endif

        return Convert.ToBase64String(sha256SigPrefix.Concat(message).ToArray());
    }
}