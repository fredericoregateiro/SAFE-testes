using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SolRIA.SAFE;
using SolRIA.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Models;
using System.Diagnostics;

namespace SAFE;

public static class DocumentSign
{
    private static IServiceProvider InitServices(string configFolder, bool testMode = true)
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

    public static async Task SignDocument(string configFolder, string pdfPath, bool testMode)
    {
        var serviceProvider = InitServices(configFolder, testMode);

        var client = serviceProvider.GetService<ISAFE_Connect>();
        var databaseService = serviceProvider.GetService<IDatabaseService>();

        // load the configuration objects
        var auth = databaseService.LoadBasicAuth();
        var config = databaseService.LoadConfig();
        var certificates = databaseService.LoadCertificates();
        var signatureConfig = databaseService.LoadSignatureConfig();

        // init the client
        client.Init(auth);

        // check for valid tokens, refresh if needed
        try
        {
            await SAFE_ListCredential(auth.ClientName, config, client);
        }
        catch (ApiException ex) when (ex.StatusCode is
            System.Net.HttpStatusCode.Unauthorized or
            System.Net.HttpStatusCode.BadRequest)
        {
            // refresh token
            await SAFE_RefreshToken(config, auth.ClientName, client, databaseService);
        }

        // check for valid algo and certificates
        if (string.IsNullOrWhiteSpace(config.CertAlgo) || certificates == null || certificates.Count == 0)
        {
            await SAFE_InfoCredentials(config, auth.ClientName, client, databaseService);

            certificates = databaseService.LoadCertificates();
            config = databaseService.LoadConfig();
        }

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

        await SAFE_Authorize(hashes, documentNames, config, processId, auth.ClientName, client);

        Thread.Sleep(1000);

        var sad = await SAFE_VerifyAuth(processId, config, client);

        Thread.Sleep(1000);

        await SAFE_SignHash(sad, hashes, config, processId, auth.ClientName, client);

        Thread.Sleep(1000);

        var signedHash = await SAFE_VerifyHash(processId, config, client);

        // after loading the hash, create the file with the signed hash returned from the service
        client.CreatePdfSigned(signedHash, inputFileStream, signedFileStream, certificates);

        // close the pdf file with empty signature
        inputFileStream.Close();
        File.Delete(Path.Combine(folder, $"{filename}-empty.pdf"));
    }

    public static void UpdateAuth(string configFolder, string clientName, string username, string password)
    {
        var serviceProvider = InitServices(configFolder);

        var databaseService = serviceProvider.GetService<IDatabaseService>();
        databaseService.UpdateBasicAuth(new BasicAuth { ClientName = clientName, Password = password, Username = username });
    }

    public static void UpdateCredentials(string configFolder, string credentialID, string accessToken, string refreshToken)
    {
        var serviceProvider = InitServices(configFolder);

        var databaseService = serviceProvider.GetService<IDatabaseService>();

        var config = databaseService.LoadConfig();
        config.CredentialID = credentialID;
        config.AccessToken = accessToken;
        config.RefreshToken = refreshToken;

        databaseService.UpdateConfig(config);
    }

    public static void UpdateSignature(string configFolder, string contactInfo, string locationInfo, string reason, string timeStampServer, bool enableLtv, float signatureX, float signatureY, float signatureWidth, float signatureHeight, string signatureImage)
    {
        var serviceProvider = InitServices(configFolder);

        var databaseService = serviceProvider.GetService<IDatabaseService>();
        databaseService.UpdateSignatureConfig(new SolRIA.SAFE.Models.SignatureConfig
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

    private static async Task SAFE_Info(Config config, ISAFE_Connect client)
    {
        var response = await client.Info(config);

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

    private static async Task SAFE_RefreshToken(Config config, string clientName, ISAFE_Connect client, IDatabaseService databaseService)
    {
        var body = new UpdateTokenRequestDto
        {
            CredentialID = config.CredentialID,
            ClientData = new ClientDataRequestBaseDto
            {
                ClientName = clientName,
                ProcessId = Guid.NewGuid().ToString(),
            }
        };

        var response = await client.UpdateToken(body, config);

        Debug.WriteLine("NewAccessToken: {0}", response.NewAccessToken);
        Debug.WriteLine("NewRefreshToken: {0}", response.NewRefreshToken);

        config.AccessToken = response.NewAccessToken;
        config.RefreshToken = response.NewRefreshToken;

        databaseService.UpdateConfig(config);
    }

    private static async Task<string> SAFE_ListCredential(string clientName, Config config, ISAFE_Connect client)
    {
        var body = new CredentialsListRequestDto
        {
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = Guid.NewGuid().ToString(),
                ClientName = clientName
            }
        };

        var response = await client.ListCredential(body, config);

        Debug.WriteLine("CredentialIDs:");
        foreach (var item in response.CredentialIDs)
        {
            Debug.WriteLine($"\t{item}");
        }

        return response.CredentialIDs.FirstOrDefault();
    }

    private static async Task SAFE_InfoCredentials(Config config, string clientName, ISAFE_Connect client, IDatabaseService databaseService)
    {
        var body = new CredentialsInfoRequestDto
        {
            Certificates = "chain",
            CredentialID = config.CredentialID,
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = Guid.NewGuid().ToString(),
                ClientName = clientName
            }
        };

        Debug.WriteLine("Call with CredentialID: {0}", body.CredentialID);
        Debug.WriteLine("Call with ProcessId: {0}", body.ClientData.ProcessId);

        var response = await client.InfoCredentials(body, config);

        Debug.WriteLine("AuthMode: {0}", response.AuthMode);
        Debug.WriteLine("Multisign: {0}", response.Multisign);
        Debug.WriteLine("Key Algo: {0}", response.Key.Algo);
        Debug.WriteLine("Key Len: {0}", response.Key.Len);
        Debug.WriteLine("Key Status: {0}", response.Key.Status);

        config.CertAlgo = response.Key.Algo;
        config.CertLen = response.Key.Len;
        config.CertStatus = response.Key.Status;

        databaseService.UpdateConfig(config);

        var certificates = response.Cert.Certificates.Select((c, i) => new Certificate
        {
            CertificateData = Convert.FromBase64String(c),
            Order = i
        });

        databaseService.UpdateCertificates(certificates);
    }

    private static async Task SAFE_Authorize(string[] hashes, string[] documentNames, Config config, string processId, string clientName, ISAFE_Connect client)
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

        await client.Authorize(body, config);
    }

    private static async Task<string> SAFE_VerifyAuth(string processId, Config config, ISAFE_Connect client)
    {
        var response = await client.VerifyAuth(processId, config);

        Debug.WriteLine("SAD: {0}", response.Sad);

        return response.Sad;
    }

    private static async Task SAFE_SignHash(string sad, string[] hashes, Config config, string processId, string clientName, ISAFE_Connect client)
    {
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
        await client.SignHash(body, config);
    }

    private static async Task<string> SAFE_VerifyHash(string processId, Config config, ISAFE_Connect client)
    {
        var response = await client.VerifyHash(processId, config);

        Debug.WriteLine("Signatures:");
        foreach (var item in response.Signatures)
        {
            Debug.WriteLine(item);
        }

        return response.Signatures.FirstOrDefault();
    }
}