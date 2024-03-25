using SolRIA.SAFE;
using SolRIA.SAFE.Interfaces;
using SolRIA.SAFE.Models;
using SolRIA.SAFE2;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace SAFE;

/// <summary>
/// 
/// </summary>
public class DocumentSign
{
    private IDatabaseService GetDatabaseService(string configFolder)
    {
        var databaseService = new DatabaseService(configFolder);
        databaseService.Init();

        return databaseService;
    }

    private ISAFE_Connect GetSAFE_Connect(bool testMode, bool log = false)
    {
        var httpClient = new HttpClient(new LoggingHandler(new HttpClientHandler(), log))
        {
            BaseAddress = new Uri(testMode ? "https://pprsafe.autenticacao.gov.pt" : "https://safe.autenticacao.gov.pt")
        };
        var httpClientOauth = new HttpClient(new LoggingHandler(new HttpClientHandler(), log))
        {
            BaseAddress = new Uri(testMode ? "https://preprod.autenticacao.gov.pt" : "https://autenticacao.gov.pt")
        };

        return new SAFE_Connect(httpClient, httpClientOauth);
    }

    /// <summary>
    /// Cria url para autenticação
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="nif">NIF usado para criar a conta</param>
    /// <param name="email">Email que fica associado a conta</param>
    /// <param name="info">Informações adicionais associadas a conta</param>
    /// <param name="redirectUri">Endereço invocado pelo serviço SAFE com o resultado da criação da conta</param>
    /// <param name="testMode">Usado ligar ao servidor de testes</param>
    /// <returns>Endereço com todos os parâmetros para criar a conta</returns>
    public string BuildAuthUrl(string configFolder, string nif, string email, string info, string redirectUri, bool testMode)
    {
        var client = GetSAFE_Connect(testMode);
        var databaseService = GetDatabaseService(configFolder);

        var basicAuth = databaseService.LoadBasicAuth();
        client.Init(basicAuth);

        var body = new AccountCreationRequest
        {
            Email = email,
            NIF = nif,
            Info = info,
            Valid = AccountCreationRequest.FillValid()
        };

        return client.CreateAccountUrl(body, redirectUri);
    }

    /// <summary>
    /// Lê o endereço devolvido pelo serviço SAFE depois de o utilizador ter feito a autenticação com sucesso e 
    /// de ter sido feito o pedido de criação da conta usando o url criado com o método <see cref="BuildAuthUrl(string, string, string, string, string, bool)"/>
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="url">Url devolvido pelo serviço SAFE</param>
    /// <param name="password">Password que vai encriptar os tokens de acesso ao serviço</param>
    /// <param name="testMode">Usado ligar ao servidor de testes</param>
    /// <param name="log">Fazer log dos pedidos http</param>
    /// <returns>Resultado da criação da conta no serviço SAFE</returns>
    public async Task<MessageResult> CreateAccountAsync(string configFolder, string url, string password, bool testMode, bool log)
    {
        try
        {
            var client = GetSAFE_Connect(testMode, log);
            var databaseService = GetDatabaseService(configFolder);

            var basicAuth = databaseService.LoadBasicAuth();
            client.Init(basicAuth);

            var token = client.ParseOauthResult(url);

            if (token.Success == false)
            {
                return new MessageResult { Success = false, Message = token.Message };
            }

            if (string.IsNullOrWhiteSpace(token.Message))
            {
                return new MessageResult { Success = false, Message = "Não foi possível ler o url de autenticação" };
            }

            // esperar 15s depois do pedido de criação de conta
            // "SAFE Documento de integração.pdf" 4.1.1.4 (Fluxo de Criação de conta) - ponto 15
            await Task.Delay(15000).ConfigureAwait(false);

            var accountRequest = await client.SendCreateAccountRequest(token.Message).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(accountRequest?.Token) || string.IsNullOrWhiteSpace(accountRequest?.AuthenticationContextId))
            {
                return new MessageResult { Success = false, Message = "Não foi possível ler o identificador do processo de autenticação" };
            }

            AccountCreationResult accountResult = null;
            var attemptNumber = 1;
            while (string.IsNullOrWhiteSpace(accountResult?.AccessToken) && attemptNumber <= 30)
            {
                accountResult = await client.ReadAccount(accountRequest).ConfigureAwait(false);

                // check for error
                if (string.IsNullOrWhiteSpace(accountResult?.Error) == false)
                {
                    return new MessageResult { Success = false, Message = $"{accountResult.Error} {accountResult.ErrorDescription}" };
                }

                // verificar se os tokens foram devolvidos, caso contrário esperar 2s até a um máximo de 30 tentativas = 60s
                // "Guia rápido de utilização OAuth2.pdf" pág. 5 ponto 9
                if (string.IsNullOrWhiteSpace(accountResult?.AccessToken))
                    await Task.Delay(2000).ConfigureAwait(false);

                attemptNumber++;
            }

            if (string.IsNullOrWhiteSpace(accountResult?.AccessToken))
            {
                return new MessageResult { Success = false, Message = "Não foi possível obter os tokens de acesso" };
            }

            // guardar os tokens
            var config = databaseService.LoadConfig(password);
            config.AccessToken = accountResult.AccessToken;
            config.RefreshToken = accountResult.RefreshToken;
            config.AccountExpirationDate = accountResult.AccountExpirationDate.ToString("yyyy-MM-dd HH:mm:ss");
            config.UpdatedAt = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            // obter o credential ID com o access token recebido
            var credentialID = await SAFE_ListCredential(basicAuth.ClientName, config, client).ConfigureAwait(false);

            // guardar o credential ID
            config.CredentialID = credentialID;

            // guardar a configuração
            databaseService.UpdateConfig(config, password);
            // clear any certificates
            databaseService.ClearCertificates();

            return new MessageResult { Success = true };
        }
        catch (Exception ex)
        {
            return new MessageResult { Success = false, Message = ex.Message };
        }
    }

    //public MessageResult CreateAccount(string configFolder, string nif, string email, string info, string password, bool testMode)
    //{
    //    var task = CreateAccountAsync(configFolder, nif, email, info, password, testMode);
    //    task.Wait();

    //    return task.Result;
    //}

    //public async Task<MessageResult> CreateAccountAsync(string configFolder, string nif, string email, string info, string password, bool testMode)
    //{
    //    //int port = GetRandomUnusedPort();
    //    int port = 62941;
    //    string redirectUri = $"http://localhost:{port}";
    //    var url = BuildAuthUrl(configFolder, nif, email, info, Uri.EscapeDataString(redirectUri), testMode);

    //    //start system browser 
    //    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

    //    using var httpListener = new HttpListener();
    //    httpListener.Prefixes.Add($"{redirectUri}/");

    //    httpListener.Start();
    //    Console.WriteLine("Start listen at: {0}", redirectUri);

    //    //wait for server captures redirect_uri  
    //    HttpListenerContext context = await httpListener.GetContextAsync();

    //    /*

    //     http://localhost:62941/#access_token=b6fbcedb-e814-40b3-b3d7-e1eb7acd0975&token_type=bearer&expires_in=7200&state=&refresh_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjgwRDU4Njg3NTM0NDg1N0RCMjlCN0VBRDYzRDUwRkIxQ0I3NjdERjQiLCJ4NXQiOiJnTldHaDFORWhYMnltMzZ0WTlVUHNjdDJmZlEiLCJ0eXAiOiJKV1QifQ.eyJyZWZyZXNoX3Rva2VuIjoiYWI1MGM1NjItYTVhNC00ZTA4LWFhMWQtZTE5M2I2ZTg4ZGVlIn0.m2Wm_enzmk247pYF5F0sOOZjvMwz5bvsV7_uCGsoa5k1r4nvJeyvd6I2oAxpCm26gcd-vYVtrJnYyrh4KFDUk4QyhtRUMdCM1RDwk4KNnQZaP_1HmdYZdd5nj2bBPsPPreq5fl9HwNG3k5MIUGvwdW_lnhoIIaAc95tEKl-T3jtB6Mzlgm-qP-zn3ZMdlH5djvmoF7JW-nEEj2BQXOiLFPHGURGC__JvCKUUOBrgXys1bj2jPk9j9AxrK9BVz_tdORhc74VHsHhpxBabfQXDnx2ILvqS3pFGxLy_R2AcarR91kWFpw0ZMfW-DkAx-Mq-41Imy-Xdb2dv7Xim3HAhyQ
    //     */

    //    // Sends an HTTP response to the browser.
    //    //var response = context.Response;
    //    //string responseString = """
    //    //    <html>
    //    //        <head>
    //    //            <meta http-equiv='refresh' content='10;url=https://www.solria.pt'>
    //    //        </head>
    //    //        <body>Já pode fechar</body>
    //    //    </html>
    //    //    """;
    //    //byte[] buffer = Encoding.UTF8.GetBytes(responseString);
    //    //response.ContentLength64 = buffer.Length;
    //    //var responseOutput = response.OutputStream;
    //    //await responseOutput.WriteAsync(buffer, 0, buffer.Length);
    //    //responseOutput.Close();

    //    var rawUrl = context.Request.Url.Fragment;
    //    var code = context.Request.QueryString.Get("access_token");
    //    httpListener.Stop();

    //    return new MessageResult { Message = code, Success = true };
    //}

    //public void StartTcpServer()
    //{
    //    IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
    //    TcpListener listener = new TcpListener(ipAddress, 500);

    //    listener.Start();

    //    // Buffer for reading data
    //    byte[] bytes = new byte[256];
    //    string data = null;
    //    while (true)
    //    {
    //        Console.WriteLine("Server is listening on " + listener.LocalEndpoint);

    //        Console.WriteLine("Waiting for a connection...");

    //        using var client = listener.AcceptTcpClient();
    //        // Get a stream object for reading and writing
    //        NetworkStream stream = client.GetStream();

    //        int i;

    //        // Loop to receive all the data sent by the client.
    //        while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
    //        {
    //            // Translate data bytes to a ASCII string.
    //            data = System.Text.Encoding.ASCII.GetString(bytes, 0, i);
    //            Console.WriteLine("Received: {0}", data);

    //            // Process the data sent by the client.
    //            data = data.ToUpper();

    //            byte[] msg = System.Text.Encoding.ASCII.GetBytes(data);

    //            // Send back a response.
    //            stream.Write(msg, 0, msg.Length);
    //            Console.WriteLine("Sent: {0}", data);
    //        }


    //    }

    //    listener.Stop();
    //}

    //private int GetRandomUnusedPort()
    //{
    //    var listener = new TcpListener(IPAddress.Loopback, 0);
    //    listener.Start();
    //    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    //    listener.Stop();
    //    return port;
    //}

    /// <summary>
    /// Cancela a conta previamente criada
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="password">Password usada na encriptação dos tokens de acesso ao serviço SAFE</param>
    /// <param name="testMode">Usado ligar ao servidor de testes</param>
    /// <returns>Resultado do pedido</returns>
    public string CancelAccount(string configFolder, string password, bool testMode)
    {
        var task = CancelAccountAsync(configFolder, password, testMode);
        task.Wait();

        return task.Result;
    }

    /// <summary>
    /// Versão assíncrona do método <see cref="CancelAccount(string, string, bool)"/>
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="password">Password usada na encriptação dos tokens de acesso ao serviço SAFE</param>
    /// <param name="testMode">Usado ligar ao servidor de testes</param>
    /// <returns>Resultado do pedido</returns>
    public async Task<string> CancelAccountAsync(string configFolder, string password, bool testMode)
    {
        try
        {
            var client = GetSAFE_Connect(testMode);
            var databaseService = GetDatabaseService(configFolder);

            var config = databaseService.LoadConfig(password);

            var basicAuth = databaseService.LoadBasicAuth();
            client.Init(basicAuth);

            var body = new CancelCitizenAccountRequestDto
            {
                CredentialID = config.CredentialID,
                ClientData = new ClientDataRequestBaseDto
                {
                    ClientName = basicAuth.ClientName,
                    ProcessId = Guid.NewGuid().ToString(),
                }
            };

            return await client.CancelAccount(body, config);
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    /// <summary>
    /// Assina digitalmente um documento PDF usando o serviço SAFE com as credenciais gravadas previamente
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="pdfPath">Caminho para o ficheiro PDF que deve ser assinado digitalmente</param>
    /// <param name="password">Password usada na encriptação dos tokens de acesso ao serviço SAFE</param>
    /// <param name="testMode">Usado ligar ao servidor de testes</param>
    public void SignDocument(string configFolder, string pdfPath, string password, bool testMode)
    {
        SignDocumentAsync(configFolder, pdfPath, password, testMode).Wait();
    }

    /// <summary>
    /// Versão assíncrona do método <see cref="SignDocument(string, string, string, bool)"/>
    /// </summary>
    /// <param name="configFolder"></param>
    /// <param name="pdfPath"></param>
    /// <param name="password"></param>
    /// <param name="testMode"></param>
    /// <returns></returns>
    public async Task SignDocumentAsync(string configFolder, string pdfPath, string password, bool testMode)
    {
        try
        {
            var client = GetSAFE_Connect(testMode);
            var databaseService = GetDatabaseService(configFolder);

            // load the configuration objects
            var auth = databaseService.LoadBasicAuth();
            var config = databaseService.LoadConfig(password);
            var certificates = databaseService.LoadCertificates();
            var signatureConfig = databaseService.LoadSignatureConfig();

            // load the syncfusion license key
            if (string.IsNullOrWhiteSpace(signatureConfig.SyncfusionKey) == false)
                Syncfusion.Licensing.SyncfusionLicenseProvider.RegisterLicense(signatureConfig.SyncfusionKey);

            // init the client
            client.Init(auth);

            // check for valid tokens, refresh if needed
            await CheckTokens(password, client, databaseService, auth, config).ConfigureAwait(false);

            // check for valid algo and certificates
            (config, certificates) = await CheckCertificates(password, client, databaseService, certificates, auth, config).ConfigureAwait(false);

            // get the stream from a documents
            var folder = Path.GetDirectoryName(pdfPath);
            var filename = Path.GetFileNameWithoutExtension(pdfPath);
            using var documentStream = new FileStream(pdfPath, FileMode.Open, FileAccess.Read);
            using var inputFileStream = new FileStream(Path.Combine(folder, $"{filename}-empty.pdf"), FileMode.Create, FileAccess.ReadWrite);
            using var signedFileStream = new FileStream(Path.Combine(folder, $"{filename}-signed.pdf"), FileMode.Create, FileAccess.ReadWrite);

            // create a pdf with empty signature
            var initialHash = client.CreatePdfEmptySignature(documentStream, inputFileStream, certificates, signatureConfig);

            // calculate the has of the pdf document with a empty signature
            var hashes = new string[]
            {
                client.CalculateHash(initialHash),
            };

            // get the original filename
            var documentNames = new string[] { $"{filename}.pdf" };

            // processId must be unique to one sign session
            var processId = Guid.NewGuid().ToString();

            await SAFE_Authorize(hashes, documentNames, config, processId, auth.ClientName, client).ConfigureAwait(false);

            var sad = await SAFE_VerifyAuth(processId, config, client).ConfigureAwait(false);

            await SAFE_SignHash(sad, hashes, config, processId, auth.ClientName, client).ConfigureAwait(false);

            var signedHash = await SAFE_VerifyHash(processId, config, client).ConfigureAwait(false);

            // after loading the hash, create the file with the signed hash returned from the service
            client.CreatePdfSigned(signedHash, inputFileStream, signedFileStream, certificates);

            // close the pdf file with empty signature
            inputFileStream.Close();
            File.Delete(Path.Combine(folder, $"{filename}-empty.pdf"));
        }
        catch (Exception ex)
        {
            LogService.Log(ex);
        }
    }

    private async Task CheckTokens(string password, ISAFE_Connect client, IDatabaseService databaseService, BasicAuth auth, Config config)
    {
        try
        {
            await SAFE_ListCredential(auth.ClientName, config, client).ConfigureAwait(false);
        }
        catch (ApiException ex) when (ex.StatusCode is
            System.Net.HttpStatusCode.Unauthorized or
            System.Net.HttpStatusCode.BadRequest)
        {
            // refresh token
            await SAFE_RefreshToken(config, auth.ClientName, password, client, databaseService).ConfigureAwait(false);
        }
    }

    private async Task<(Config, List<X509Certificate2>)> CheckCertificates(string password, ISAFE_Connect client, IDatabaseService databaseService, List<X509Certificate2> certificates, BasicAuth auth, Config config)
    {
        if (string.IsNullOrWhiteSpace(config.CertAlgo) || certificates == null || certificates.Count == 0)
        {
            await SAFE_InfoCredentials(config, auth.ClientName, password, client, databaseService).ConfigureAwait(false);

            certificates = databaseService.LoadCertificates();
            config = databaseService.LoadConfig(password);
        }

        return (config, certificates);
    }

    /// <summary>
    /// Grava as credenciais no ficheiro de configuração da SW que foi previamente autorizada pelo serviço SAFE. 
    /// Estas credenciais serão utilizadas posteriormente para invocar os serviços SAFE como <see cref="SignDocument(string, string, string, bool)"/>
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="clientName">Nome do cliente, fornecido pelo serviço SAFE</param>
    /// <param name="clientId">Id do cliente, fornecido pelo serviço SAFE</param>
    /// <param name="username">Utilizador, fornecido pelo serviço SAFE</param>
    /// <param name="password">Password, fornecido pelo serviço SAFE</param>
    public void UpdateAuth(string configFolder, string clientName, string clientId, string username, string password)
    {
        var databaseService = GetDatabaseService(configFolder);
        databaseService.UpdateBasicAuth(new BasicAuth { ClientName = clientName, ClientId = clientId, Password = password, Username = username });
    }

    /// <summary>
    /// Devolve as credenciais guardadas no ficheiro de configuração
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <returns>Objecto com as credenciais fornecidas pelo serviço SAFE</returns>
    public BasicAuth GetAuth(string configFolder)
    {
        var databaseService = GetDatabaseService(configFolder);

        return databaseService.LoadBasicAuth();
    }

    /// <summary>
    /// Grava as credenciais da conta de assinatura criada no SAFE, no ficheiro de configuração.
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="credentialID">O ID, criado pelo serviço SAFE na criação da conta</param>
    /// <param name="accessToken">Token de acesso, criado pelo serviço SAFE na criação da conta</param>
    /// <param name="refreshToken">Token de refresh usado quando o <paramref name="accessToken"/> está expirado, criado pelo serviço SAFE na criação da conta</param>
    /// <param name="password">Password que vai encriptar os tokens <paramref name="accessToken"/> e <paramref name="refreshToken"/></param>
    public void UpdateCredentials(string configFolder, string credentialID, string accessToken, string refreshToken, string password)
    {
        var databaseService = GetDatabaseService(configFolder);

        var config = databaseService.LoadConfig(password);
        config.CredentialID = credentialID;
        config.AccessToken = accessToken;
        config.RefreshToken = refreshToken;

        databaseService.UpdateConfig(config, password);
    }

    /// <summary>
    /// Devolve as credenciais da conta de assinatura no SAFE guardadas no ficheiro de configuração
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="password"></param>
    /// <returns>Objeto com as credenciais da conta de assinatura</returns>
    public Config GetCredentials(string configFolder, string password)
    {
        var databaseService = GetDatabaseService(configFolder);

        return databaseService.LoadConfig(password);
    }

    /// <summary>
    /// Guarda os dados usados para criar a assinatura digital no documento PDF.
    /// Esta informação será utilizada no momento de assinatura no método <see cref="SignDocument(string, string, string, bool)"/>
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <param name="contactInfo">Informação do contato que ficará na assinatura digital</param>
    /// <param name="locationInfo">Informação da localização que ficará na assinatura digital</param>
    /// <param name="reason">Informação da razão da assinatura que ficará na assinatura digital</param>
    /// <param name="timeStampServer">Endereço do servidor temporal, caso se queira criar uma assinatura com validação temporal</param>
    /// <param name="enableLtv">Flag que ativa o parâmetro LTV na assinatura digital</param>
    /// <param name="signatureX">Coordenada x para a posição da imagem da assinatura começando pelo canto superior esquerdo do documento</param>
    /// <param name="signatureY">Coordenada y para a posição da imagem da assinatura começando pelo canto superior esquerdo do documento</param>
    /// <param name="signatureWidth">Largura da imagem da assinatura</param>
    /// <param name="signatureHeight">Altura da imagem da assinatura</param>
    /// <param name="signatureImage">Caminho para a imagem a ser utilizada como visual da assinatura eletrónica</param>
    public void UpdateSignature(string configFolder, string contactInfo, string locationInfo, string reason, string timeStampServer, bool enableLtv, float signatureX, float signatureY, float signatureWidth, float signatureHeight, string signatureImage, string syncfusionKey)
    {
        var databaseService = GetDatabaseService(configFolder);
        databaseService.UpdateSignatureConfig(new SignatureConfig
        {
            ContactInfo = contactInfo,
            LocationInfo = locationInfo,
            Reason = reason,
            TimeStampServer = timeStampServer,
            EnableLtv = enableLtv,
            SignatureX = signatureX,
            SignatureY = signatureY,
            SignatureWidth = signatureWidth,
            SignatureHeight = signatureHeight,
            SignatureImage = File.Exists(signatureImage) ? File.ReadAllBytes(signatureImage) : null,
            SyncfusionKey = syncfusionKey
        });
    }

    /// <summary>
    /// Obtém as informações guardadas no ficheiro de configuração sobre a assinatura digital pelo método <see cref="UpdateSignature(string, string, string, string, string, bool, float, float, float, float, string)"/>
    /// </summary>
    /// <param name="configFolder">Caminho da pasta que contém o ficheiro de configuração</param>
    /// <returns>Objeto com as informações da assinatura</returns>
    public SignatureConfig GetSignature(string configFolder)
    {
        var databaseService = GetDatabaseService(configFolder);

        return databaseService.LoadSignatureConfig();
    }

    private async Task SAFE_Info(Config config, ISAFE_Connect client)
    {
        var response = await client.Info(config).ConfigureAwait(false);

        Debug.WriteLine("Description: {0}", response.Description);
        Debug.WriteLine("Name: {0}", response.Name);
        Debug.WriteLine("Region: {0}", response.Region);
        Debug.WriteLine("Lang: {0}", response.Lang);
        Debug.WriteLine("Specs: {0}", response.Specs);
        Debug.WriteLine("Logo: {0}", response.Logo);

        Debug.WriteLine("Methods:");
        foreach (var item in response.Methods)
        {
            Debug.WriteLine($"\t{item}");
        }

        Debug.WriteLine("AuthType:");
        foreach (var item in response.AuthType)
        {
            Debug.WriteLine($"\t{item}");
        }
    }

    private async Task SAFE_RefreshToken(Config config, string clientName, string password, ISAFE_Connect client, IDatabaseService databaseService)
    {
        var body = new UpdateTokenRequestDto
        {
            CredentialID = config.CredentialID,
            ClientData = new ClientDataRequestBaseDto
            {
                ClientName = clientName,
                ProcessId = Guid.NewGuid().ToString(),
            },
        };

        var response = await client.UpdateToken(body, config).ConfigureAwait(false);

        config.AccessToken = response.NewAccessToken;
        config.RefreshToken = response.NewRefreshToken;

        databaseService.UpdateConfig(config, password);
    }

    private async Task<string> SAFE_ListCredential(string clientName, Config config, ISAFE_Connect client)
    {
        var body = new CredentialsListRequestDto
        {
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = Guid.NewGuid().ToString(),
                ClientName = clientName,
            },
        };

        var response = await client.ListCredential(body, config).ConfigureAwait(false);

        Debug.WriteLine("CredentialIDs:");
        foreach (var item in response.CredentialIDs)
        {
            Debug.WriteLine($"\t{item}");
        }

        return response.CredentialIDs.FirstOrDefault();
    }

    private async Task SAFE_InfoCredentials(Config config, string clientName, string password, ISAFE_Connect client, IDatabaseService databaseService)
    {
        var body = new CredentialsInfoRequestDto
        {
            Certificates = "chain",
            CredentialID = config.CredentialID,
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = Guid.NewGuid().ToString(),
                ClientName = clientName,
            },
        };

        Debug.WriteLine("Call with CredentialID: {0}", body.CredentialID);
        Debug.WriteLine("Call with ProcessId: {0}", body.ClientData.ProcessId);

        var response = await client.InfoCredentials(body, config).ConfigureAwait(false);

        Debug.WriteLine("AuthMode: {0}", response.AuthMode);
        Debug.WriteLine("Multisign: {0}", response.Multisign);
        Debug.WriteLine("Key Algo: {0}", response.Key.Algo);
        Debug.WriteLine("Key Len: {0}", response.Key.Len);
        Debug.WriteLine("Key Status: {0}", response.Key.Status);

        config.CertAlgo = response.Key.Algo;
        config.CertLen = response.Key.Len;
        config.CertStatus = response.Key.Status;

        databaseService.UpdateConfig(config, password);

        var certificates = response.Cert.Certificates.Select((c, i) => new Certificate
        {
            CertificateData = c,
            Order = i
        }).ToArray();

        databaseService.UpdateCertificates(certificates);
    }

    private async Task SAFE_Authorize(string[] hashes, string[] documentNames, Config config, string processId, string clientName, ISAFE_Connect client)
    {
        var body = new SignHashAuthorizationRequestDto
        {
            CredentialID = config.CredentialID,
            NumSignatures = documentNames.Length,
            ClientData = new SignHashAuthorizationClientDataRequestDto
            {
                ProcessId = processId,
                ClientName = clientName,
                DocumentNames = documentNames
            },
            Hashes = hashes
        };

        await client.Authorize(body, config).ConfigureAwait(false);
    }

    private async Task<string> SAFE_VerifyAuth(string processId, Config config, ISAFE_Connect client)
    {
        await Task.Delay(1000).ConfigureAwait(false);

        var response = await client.VerifyAuth(processId, config).ConfigureAwait(false);

        Debug.WriteLine("SAD: {0}", response.Sad);

        return response.Sad;
    }

    private async Task SAFE_SignHash(string sad, string[] hashes, Config config, string processId, string clientName, ISAFE_Connect client)
    {
        await Task.Delay(1000).ConfigureAwait(false);

        var body = new SignHashRequestDto
        {
            Sad = sad,
            CredentialID = config.CredentialID,
            SignAlgo = config.CertAlgo,
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = processId,
                ClientName = clientName,
            },
            Hashes = hashes
        };

        Console.WriteLine("ProcessId: {0}", body.ClientData.ProcessId);
        await client.SignHash(body, config).ConfigureAwait(false);
    }

    private async Task<string> SAFE_VerifyHash(string processId, Config config, ISAFE_Connect client)
    {
        await Task.Delay(1000).ConfigureAwait(false);

        var response = await client.VerifyHash(processId, config).ConfigureAwait(false);

        Debug.WriteLine("Signatures:");
        foreach (var item in response.Signatures)
        {
            Debug.WriteLine(item);
        }

        return response.Signatures.FirstOrDefault();
    }
}