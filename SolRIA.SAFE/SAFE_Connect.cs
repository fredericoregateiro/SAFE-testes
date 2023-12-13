using Dapper;
using SolRIA.SAFE.Models;
using SolRIA.Sign.SAFE;
using SolRIA.Sign.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Models;
using Syncfusion.Pdf.Graphics;
using Syncfusion.Pdf.Parsing;
using Syncfusion.Pdf.Security;
using System.Drawing;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace SAFE;

public class SAFE_Connect : ISAFE_Connect
{
    private BasicAuth _auth;

    private readonly HttpClient _httpClient;
    private readonly HttpClient _httpClientOauth;
    public SAFE_Connect(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient("safe");
        _httpClientOauth = httpClientFactory.CreateClient("oauth");
    }

    public void Init(BasicAuth auth)
    {
        _auth = auth;
    }

    private JsonSerializerOptions serializerOptions;

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
    /// <returns>Url usado no pedido de autenticação oauth</returns>
    public string CreateAccountUrl(AccountCreationRequest creationRequest)
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

        return $"{baseAddress}/oauth/askauthorization?client_id={_auth.ClientId}&scope={scopesUrl}&response_type=token";
    }

    public MessageResult ParseOauthResult(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;

        if (url.IndexOf("/Authorized#", StringComparison.OrdinalIgnoreCase) < 0) return null;

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

        //obter a url a partir do authorized#
        var parameterStartIndex = url.IndexOf("#", StringComparison.OrdinalIgnoreCase) + 1;

        // verificar existencia de erros
        if (url.IndexOf("#error=", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            var error = url.Substring(parameterStartIndex);

            return new MessageResult { Success = false, Message = error };
        }

        // obter os tokens enviados a partir do authorized#
        var tokens = url.Substring(parameterStartIndex).Split('&');

        // só é necessário o access_token para continuar o processo de criação de conta
        var token = tokens.First(t => t.StartsWith("access_token", StringComparison.OrdinalIgnoreCase)).Split('=')[1];

        return new MessageResult { Success = true, Message = token };
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

        var content = new StringContent(JsonSerializer.Serialize(dto));
        content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json");
        request.Content = content;

        var result = await _httpClientOauth.SendAsync(request).ConfigureAwait(false);

        var resultJson = await result.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<AttributeManagerResult>(resultJson);
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

        var attributesResult = JsonSerializer.Deserialize<AttributeResult[]>(resultJson);

        var attr = attributesResult.FirstOrDefault(a => a.Name.StartsWith("http://interop.gov.pt/SAFE/createSignatureAccount", StringComparison.OrdinalIgnoreCase));

        return JsonSerializer.Deserialize<AccountCreationResult>(attr.Value);
    }

    /// <summary>
    /// Método que permite o cancelamento de uma conta de assinatura.
    /// </summary>
    public async Task<string> CancelAccount(CancelCitizenAccountRequestDto body, Config config)
    {
        return await CancelAccount(body, config, CancellationToken.None).ConfigureAwait(false);
    }
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
        if (response.StatusCode == HttpStatusCode.BadRequest) return "Bad Request";
        if (response.StatusCode == HttpStatusCode.InternalServerError) return "Internal Server Error";

        return "Invalid response";
    }

    /// <summary>
    /// Método que retorna informação sobre o serviço e a lista de todos os métodos implementados.
    /// </summary>
    public async Task<InfoResponseDto> Info(Config config)
    {
        return await Info(config, CancellationToken.None).ConfigureAwait(false);
    }
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
    /// que terá de ser enviado pelo Software de Faturação no pedido de assinatura <see cref="SignHash"/>. 
    /// Um SAD é único para cada pedido assinatura.
    /// </summary>
    public async Task<string> Authorize(SignHashAuthorizationRequestDto body, Config config)
    {
        return await Authorize(body, config, CancellationToken.None).ConfigureAwait(false);
    }
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
    /// de pedido de autorização <see cref="Authorize"/>. 
    /// O SAFE devolve o Signature Activation Data (SAD) que terá de ser enviado pelo Software
    /// de Faturação no pedido de assinatura <see cref="SignHash"/>.
    /// Um SAD é único para cada pedido assinatura. 
    /// Este método deve ser invocado do seguinte modo: 
    /// A primeira invocação deve ser feita 1 segundo após a invocação do método de pedido de autorização <see cref="Authorize"/>.
    /// Se o SAFE devolver um código HTTP 204 No Content (ou seja, não devolver o SAD), 
    /// o pedido deve ser repetido mais 4 vezes (total de 5 vezes), com intervalos de 1 segundo.
    /// </summary>
    public async Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, Config config)
    {
        return await VerifyAuth(processId, config, CancellationToken.None).ConfigureAwait(false);
    }
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
    /// Este método que deve ser invocado após a invocação do método de verificação de autorização <see cref="VerifyAuth"/>,
    /// verifica se o SAD recebido corresponde ao que foi gerado no método de autorização, e assina a(s) hash(es) assinada(s).
    /// </summary>
    public async Task<string> SignHash(SignHashRequestDto body, Config config)
    {
        return await SignHash(body, config, CancellationToken.None).ConfigureAwait(false);
    }
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
    public async Task<SignHashResponseDto> VerifyHash(string processId, Config config)
    {
        return await VerifyHash(processId, config, CancellationToken.None).ConfigureAwait(false);
    }
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

    private void AddAuthenticationHeaders(HttpRequestMessage request)
    {
        AddAuthenticationHeaders(request, token: null);
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
        var json = JsonSerializer.Serialize(body, serializerOptions);
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
            throw new ApiException($"The HTTP status code of the response was not expected ({(int)response.StatusCode}).", response.StatusCode, responseData, headers, innerException: null);
        }

        var responseText = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        try
        {
            serializerOptions ??= new JsonSerializerOptions
            {
                Converters =
                {
                    new DateTimeFormat(),
                },
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
            signature.CreateLongTermValidity(certificates.AsList());

        //Create an external signer.
        var emptySignature = new SignEmpty();
        //Add public certificates.
        signature.AddExternalSigner(emptySignature, certificates.AsList(), Ocsp: null);

        loadedDocument.Save(inputFileStream);

        //Close the PDF document.
        loadedDocument.Close(completely: true);

        return emptySignature.Message;
    }
    public void CreatePdfSigned(string signedHash, Stream inputFileStream, Stream outputFileStream, IList<X509Certificate2> certificates)
    {
        //Create an external signer with a signed hash message.
        var externalSigner = new ExternalSigner(signedHash);

        string pdfPassword = string.Empty;

        // replace an empty signature.
        PdfSignature.ReplaceEmptySignature(inputFileStream, pdfPassword, outputFileStream, "Signature", externalSigner, certificates.AsList(), isEncodeSignature: true);
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

    public string CalculateHash(byte[] message)
    {
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