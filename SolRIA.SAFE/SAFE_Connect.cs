using Dapper;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SolRIA.Sign.SAFE;
using SolRIA.Sign.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Models;
using Syncfusion.Pdf.Parsing;
using Syncfusion.Pdf.Security;
using Syncfusion.Drawing;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace SAFE;

public class SAFE_Connect : ISAFE_Connect
{
    private readonly IDatabaseConnection _configuration;
    private readonly HttpClient _httpClient;
    private readonly BasicAuth _basicAuth;
    private Config _config;

    public SAFE_Connect(IHttpClientFactory httpClientFactory, IDatabaseConnection configuration, BasicAuth basicAuth)
    {
        _httpClient = httpClientFactory.CreateClient();
        _configuration = configuration;
        _basicAuth = basicAuth;
    }

    public void InitTokens()
    {
        var connection = new SqliteConnection(_configuration.ConnectionString);
        _config = connection.QueryFirstOrDefault<Config>("SELECT * FROM safe_config;");

        _config ??= new Config();
    }

    public void UpdateTokens(string newAccessToken, string newRefreshToken)
    {
        _config.AccessToken = newAccessToken;
        _config.RefreshToken = newRefreshToken;

        var connection = new SqliteConnection(_configuration.ConnectionString);

        // save the tokens
        if (_config.Id == 0)
        {
            connection.Execute("""
            INSERT INTO safe_config 
            (AccessToken,RefreshToken) VALUES (@AccessToken,@RefreshToken);
            """);
            return;
        }

        connection.Execute("""
            UPDATE safe_config SET 
            AccessToken=@AccessToken, RefreshToken=@RefreshToken
            WHERE Id=@Id;
            """, _config);
    }

    private JsonSerializerOptions serializerOptions;

    /// <summary>
    /// Método que retorna um novo AccessToken e um novo RefreshToken para uma conta de assinatura. 
    /// Estes novos tokens devem ser utilizados nas invocações futuras aos serviços. 
    /// Este método deve ser invocado sempre que o sistema retorne o erro HTTP 400 Bad Request, 
    /// com a mensagem de erro “The access or refresh token is expired or has been revoked”
    /// </summary>
    public async Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body)
    {
        return await UpdateToken(body, CancellationToken.None);
    }
    public async Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/signatureAccount/updateToken");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationRefreshHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

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
    public async Task<string> CancelAccount(CancelCitizenAccountRequestDto body)
    {
        return await CancelAccount(body, CancellationToken.None);
    }
    public async Task<string> CancelAccount(CancelCitizenAccountRequestDto body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/signatureAccount/cancel");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
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
    public async Task<InfoResponseDto> Info()
    {
        return await Info(CancellationToken.None);
    }
    public async Task<InfoResponseDto> Info(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/info");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<InfoResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que retorna a lista de credenciais associados a uma conta de assinatura. 
    /// Cada conta de assinatura do SAFE tem apenas uma credencial, 
    /// que deve ser enviada em todos os métodos que requeiram o parâmetro credentialId
    /// </summary>
    public async Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body)
    {
        return await ListCredential(body, CancellationToken.None);
    }
    public async Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/credentials/list");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

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
    public async Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body)
    {
        return await InfoCredentials(body, CancellationToken.None);
    }
    public async Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/credentials/info");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

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
    public async Task<string> Authorize(SignHashAuthorizationRequestDto body)
    {
        return await Authorize(body, CancellationToken.None);
    }
    public async Task<string> Authorize(SignHashAuthorizationRequestDto body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v2/credentials/authorize");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

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
    public async Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId)
    {
        return await VerifyAuth(processId, CancellationToken.None);
    }
    public async Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/credentials/authorize/verify?processId=" + Uri.UnescapeDataString(processId));
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<SignHashAuthorizationResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    /// <summary>
    /// Método que pede assinatura de hash(es). 
    /// Este método que deve ser invocado após a invocação do método de verificação de autorização <see cref="VerifyAuth"/>,
    /// verifica se o SAD recebido corresponde ao que foi gerado no método de autorização, e assina a(s) hash(es) assinada(s).
    /// </summary>
    public async Task<string> SignHash(SignHashRequestDto body)
    {
        return await SignHash(body, CancellationToken.None);
    }
    public async Task<string> SignHash(SignHashRequestDto body, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v2/signatures/signHash");
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);
        AddJsonBodyToRequest(body, request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

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
    public async Task<SignHashResponseDto> VerifyHash(string processId)
    {
        return await VerifyHash(processId, CancellationToken.None);
    }
    public async Task<SignHashResponseDto> VerifyHash(string processId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/signatures/signHash/verify?processId=" + Uri.UnescapeDataString(processId));
        request.Headers.TryAddWithoutValidation("accept", "*/*");
        AddAuthenticationHeaders(request);

        var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var objectResponse = await ReadObjectResponseAsync<SignHashResponseDto>(response, cancellationToken).ConfigureAwait(false);

        GuardResultNotNull(response, objectResponse);

        return objectResponse.Object;
    }

    private void AddAuthenticationHeaders(HttpRequestMessage request)
    {
        AddAuthenticationHeaders(request, _config.AccessToken);
    }
    private void AddAuthenticationRefreshHeaders(HttpRequestMessage request)
    {
        AddAuthenticationHeaders(request, _config.RefreshToken);
    }
    private void AddAuthenticationHeaders(HttpRequestMessage request, string token)
    {
        request.Headers.TryAddWithoutValidation("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_basicAuth.Username}:{_basicAuth.Password}")));
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

    public byte[] CreatePdfEmptySignature(Stream documentStream, Stream inputFileStream)
    {
        //Load an existing PDF document.
        var loadedDocument = new PdfLoadedDocument(documentStream);

        //Creates a digital signature.
        var signature = new PdfSignature(loadedDocument, loadedDocument.Pages[0], null, "Signature")
        {
            //Sets the signature information.
            Bounds = new RectangleF(new PointF(0, 0), new SizeF(100, 30))
        };

        signature.Settings.CryptographicStandard = CryptographicStandard.CMS;
        signature.Settings.DigestAlgorithm = DigestAlgorithm.SHA256;

        signature.ContactInfo = "suporte@solria.pt";
        signature.LocationInfo = "SolRIA";
        signature.Reason = "Autor deste documento";

        // optional
        signature.TimeStampServer = new TimeStampServer(new Uri("http://ts.cartaodecidadao.pt/tsa/server"));
        signature.EnableLtv = true;

        //Create an external signer.
        var emptySignature = new SignEmpty();
        //Add public certificates.
        var certificates = LoadCertificates();
        signature.AddExternalSigner(emptySignature, certificates, null);

        loadedDocument.Save(inputFileStream);

        //Close the PDF document.
        loadedDocument.Close(true);

        return emptySignature.Message;
    }
    public void CreatePdfSigned(string signedHash, string emptyPdfSignature, string outputFile)
    {
        //Create an external signer with a signed hash message.
        var externalSigner = new ExternalSigner(signedHash);

        //Add public certificates.
        var certificates = LoadCertificates();

        // create an output file stream that will be the signed document
        using var outputFileStream = new FileStream(outputFile, FileMode.Create, FileAccess.ReadWrite);

        // get the stream from the document with the empty signature
        using var inputFileStream = new FileStream(emptyPdfSignature, FileMode.Open, FileAccess.Read);

        string pdfPassword = string.Empty;

        // replace an empty signature.
        PdfSignature.ReplaceEmptySignature(inputFileStream, pdfPassword, outputFileStream, "Signature", externalSigner, certificates, true);
    }

    private List<X509Certificate2> LoadCertificates()
    {
        var connection = new SqliteConnection(_configuration.ConnectionString);

        var certificates = connection.Query<byte[]>("""
            SELECT CertificateData FROM safe_certificates ORDER BY `Order`;
        """);

        //Create new X509Certificate2 with the root certificate
        return certificates.Select(c => new X509Certificate2(c)).AsList();
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

    public string CalculateHash(string filename)
    {
        // openssl sha256 -binary in.pdf > out.txt
        // openssl base64 -in out.txt -out out64.txt

        byte[] sha256SigPrefix = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

        using var SHA256 = System.Security.Cryptography.SHA256.Create();
        using FileStream fileStream = File.OpenRead(filename);

        var fileHashArray = SHA256.ComputeHash(fileStream);

        return Convert.ToBase64String(sha256SigPrefix.Concat(fileHashArray).ToArray());
    }

    public string CalculateHash(byte[] message)
    {
        byte[] sha256SigPrefix = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

        message = SHA256.HashData(message);

        return Convert.ToBase64String(sha256SigPrefix.Concat(message).ToArray());
    }
}