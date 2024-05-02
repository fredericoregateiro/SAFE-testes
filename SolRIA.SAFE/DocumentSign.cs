using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SolRIA.SAFE;
using SolRIA.SAFE.Interfaces;
using SolRIA.SAFE.Models;
using SolRIA.Sign.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Models;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace SAFE;

public class DocumentSign
{
    private IServiceProvider InitServices(string configFolder, bool testMode = true)
    {
        //start the services container
        return new HostBuilder()
            .ConfigureServices(s =>
            {
                Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;

                var dbFileName = Path.Combine(configFolder, "safe_config.db");
                var dbConfig = new DatabaseConfiguration
                {
                    ConnectionString = $"Data Source={dbFileName}"
                };

                s.AddHttpClient("safe", c =>
                {
                    c.BaseAddress = new Uri(testMode ? "https://pprsafe.autenticacao.gov.pt" : "https://safe.autenticacao.gov.pt");
                });
                s.AddHttpClient("oauth", c =>
                {
                    c.BaseAddress = new Uri(testMode ? "https://preprod.autenticacao.gov.pt" : "https://autenticacao.gov.pt");
                });

                s.AddSingleton<IDatabaseConnection>(dbConfig);
                s.AddSingleton<ISAFE_Connect, SAFE_Connect>();
                s.AddSingleton<IDatabaseService, DatabaseService>();
            })
            .Build()
            .Services;
    }

    public void SignDocument(string configFolder, string pdfPath, string password, bool testMode)
    {
        SignDocumentAsync(configFolder, pdfPath, password, testMode).Wait();
    }

    public async Task SignDocumentAsync(string configFolder, string pdfPath, string password, bool testMode)
    {
        var serviceProvider = InitServices(configFolder, testMode);

        var client = serviceProvider.GetService<ISAFE_Connect>();
        var databaseService = serviceProvider.GetService<IDatabaseService>();

        // load the configuration objects
        var auth = databaseService.LoadBasicAuth();
        var config = databaseService.LoadConfig(password);
        var certificates = databaseService.LoadCertificates();
        var signatureConfig = databaseService.LoadSignatureConfig();

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

    private async Task CheckTokens(string password, ISAFE_Connect client, IDatabaseService databaseService, BasicAuth auth, Config config)
    {
        try
        {
            var credentialID = await SAFE_ListCredential(auth.ClientName, config, client).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(config.CredentialID))
            {
                config.CredentialID = credentialID;
                databaseService.UpdateConfigCredentialID(config, password);
            }
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

    public void UpdateAuth(string configFolder, string clientName, string clientId, string username, string password)
    {
        var serviceProvider = InitServices(configFolder);

        var databaseService = serviceProvider.GetService<IDatabaseService>();
        databaseService.UpdateBasicAuth(new BasicAuth { ClientName = clientName, ClientId = clientId, Password = password, Username = username });
    }

    public BasicAuth GetAuth(string configFolder)
    {
        var serviceProvider = InitServices(configFolder);
        var databaseService = serviceProvider.GetService<IDatabaseService>();

        return databaseService.LoadBasicAuth();
    }

    public void UpdateCredentials(string configFolder, string credentialID, string accessToken, string refreshToken, string password)
    {
        var serviceProvider = InitServices(configFolder);

        var databaseService = serviceProvider.GetService<IDatabaseService>();

        var config = databaseService.LoadConfig(password);
        config.CredentialID = credentialID;
        config.AccessToken = accessToken;
        config.RefreshToken = refreshToken;

        databaseService.UpdateConfig(config, password);
    }

    public Config GetCredentials(string configFolder, string password)
    {
        var serviceProvider = InitServices(configFolder);
        var databaseService = serviceProvider.GetService<IDatabaseService>();

        return databaseService.LoadConfig(password);
    }

    public void UpdateSignature(string configFolder, string contactInfo, string locationInfo, string reason, string timeStampServer, bool enableLtv, float signatureX, float signatureY, float signatureWidth, float signatureHeight, string signatureImage)
    {
        var serviceProvider = InitServices(configFolder);

        var databaseService = serviceProvider.GetService<IDatabaseService>();
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
            SignatureImage = File.Exists(signatureImage) ? File.ReadAllBytes(signatureImage) : null
        });
    }

    public SignatureConfig GetSignature(string configFolder)
    {
        var serviceProvider = InitServices(configFolder);
        var databaseService = serviceProvider.GetService<IDatabaseService>();

        return databaseService.LoadSignatureConfig();
    }

    public string BuildAuthUrl(string configFolder, string nif, string email, string info)
    {
        var serviceProvider = InitServices(configFolder);

        var client = serviceProvider.GetService<ISAFE_Connect>();
        var databaseService = serviceProvider.GetService<IDatabaseService>();

        var basicAuth = databaseService.LoadBasicAuth();
        client.Init(basicAuth);

        var body = new AccountCreationRequest
        {
            Email = email,
            NIF = nif,
            Info = info,
            Valid = AccountCreationRequest.FillValid()
        };

        return client.CreateAccountUrl(body);
    }

    public async Task<MessageResult> CreateAccountAsync(string configFolder, string url, string password)
    {
        try
        {
            var serviceProvider = InitServices(configFolder);

            var client = serviceProvider.GetService<ISAFE_Connect>();
            var databaseService = serviceProvider.GetService<IDatabaseService>();

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
            await Task.Delay(TimeSpan.FromSeconds(15)).ConfigureAwait(false);

            var accountRequest = await client.SendCreateAccountRequest(token.Message).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(accountRequest?.Token) || string.IsNullOrWhiteSpace(accountRequest?.AuthenticationContextId))
            {
                return new MessageResult { Success = false, Message = "Não foi possível ler o identificador do processo de autenticação" };
            }

            AccountCreationResult accountResult = null;
            // verificar se os tokens foram devolvidos, caso contrário esperar 2s até a um máximo de 30 tentativas = 60s
            var attemptNumber = 1;
            while (string.IsNullOrWhiteSpace(accountResult?.AccessToken) && attemptNumber <= 30)
            {
                await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(false);

                accountResult = await client.ReadAccount(accountRequest).ConfigureAwait(false);

                // check for error
                if (string.IsNullOrWhiteSpace(accountResult?.Error) == false)
                {
                    return new MessageResult { Success = false, Message = $"{accountResult.Error} {accountResult.ErrorDescription}" };
                }
            }

            if (string.IsNullOrWhiteSpace(accountResult?.AccessToken))
            {
                return new MessageResult { Success = false, Message = "Não foi possível obter os tokens de acesso" };
            }

            // guardar os tokens
            var config = databaseService.LoadConfig(password);
            config.AccessToken = accountResult.AccessToken;
            config.RefreshToken = accountResult.RefreshToken;
            config.CredentialID = string.Empty;

            // guardar a configuração
            databaseService.UpdateConfig(config, password);

            // obter o credential ID com o access token recebido
            attemptNumber = 1;
            while (string.IsNullOrWhiteSpace(config.CredentialID) && attemptNumber <= 30)
            {
                try
                {
                    config.CredentialID = await SAFE_ListCredential(basicAuth.ClientName, config, client).ConfigureAwait(false);
                }
                catch { }

                // verificar se o credentialID foi devolvidos, caso contrário esperar 2s até a um máximo de 30 tentativas = 60s
                // "Guia rápido de utilização OAuth2.pdf" pág. 5 ponto 9
                if (string.IsNullOrWhiteSpace(config.CredentialID))
                    await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(false);

                attemptNumber++;
            }

            // guardar o credential ID
            if (string.IsNullOrWhiteSpace(config.CredentialID) == false)
                databaseService.UpdateConfigCredentialID(config, password);

            return new MessageResult { Success = true };
        }
        catch (Exception ex)
        {
            return new MessageResult { Success = false, Message = ex.Message };
        }
    }

    public async Task<string> CancelAccountAsync(string configFolder, string password)
    {
        try
        {
            var serviceProvider = InitServices(configFolder);

            var client = serviceProvider.GetService<ISAFE_Connect>();
            var databaseService = serviceProvider.GetService<IDatabaseService>();

            var config = databaseService.LoadConfig(password);

            var basicAuth = databaseService.LoadBasicAuth();
            client.Init(basicAuth);

            // check for valid tokens, refresh if needed
            await CheckTokens(password, client, databaseService, basicAuth, config).ConfigureAwait(false);

            var body = new CancelCitizenAccountRequestDto
            {
                CredentialID = config.CredentialID,
                ClientData = new ClientDataRequestBaseDto
                {
                    ClientName = basicAuth.ClientName,
                    ProcessId = Guid.NewGuid().ToString(),
                }
            };

            return await client.CancelAccount(body, config).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
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
            CertificateData = Convert.FromBase64String(c),
            Order = i
        });

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