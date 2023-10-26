using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SolRIA.Sign.SAFE.Interfaces;
using SolRIA.Sign.SAFE.Models;

namespace SAFE;

public static class TestsSAFE
{
    public static readonly string src = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\FT23-68.pdf";
    public static readonly string destEmpty = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\FT23-68-empty.pdf";
    public static readonly string destSigned = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\FT23-68-signed.pdf";

    private static ISAFE_Connect client;
    private static IServiceProvider InitServices()
    {
        //start the services container
        return new HostBuilder()
            .ConfigureServices(s =>
            {
                var dbConfig = new DatabaseConfiguration
                {
                    ConnectionString = @"Data Source=c:\safe.db"
                };

                var basicAuth = new BasicAuth
                {
                    Username = "clientTest",
                    Password = "Test"
                };

                s.AddHttpClient<SAFE_Connect>(c =>
                {
                    c.BaseAddress = new Uri("https://pprsafe.autenticacao.gov.pt");
                });

                s.AddSingleton(dbConfig);
                s.AddSingleton(basicAuth);

                s.AddSingleton<ISAFE_Connect, SAFE_Connect>();
            })
            .Build()
            .Services;
    }
    public static async Task SignDocument()
    {
        var serviceProvider = InitServices();

        client = serviceProvider.GetService<ISAFE_Connect>();
        client.InitTokens();

        // create a pdf with empty signature
        //Get the stream from a document.
        using var documentStream = new FileStream(src, FileMode.Open, FileAccess.Read);
        using var inputFileStream = new FileStream(destEmpty, FileMode.Create, FileAccess.ReadWrite);

        var initialHash = client.CreatePdfEmptySignature(documentStream, inputFileStream);

        // calculate the has of the pdf document with a empty signature
        var hashes = new string[]
        {
            client.CalculateHash(initialHash),
        };

        // get the original filename
        var documentNames = new string[] { Path.GetFileName(src) };

        // client name is set by the SAFE team
        var clientName = "clientTest";

        // processId must be unique to one sign session
        var processId = Guid.NewGuid().ToString();

        //TODO: the credential should be save o on the config for this client
        string credentialID;

        try
        {
            credentialID = await SAFE_ListCredential(processId, clientName);
        }
        catch (ApiException ex) when (ex.StatusCode is
            System.Net.HttpStatusCode.Unauthorized or
            System.Net.HttpStatusCode.BadRequest)
        {
            credentialID = "b63db1b2-b6e6-4124-8842-a0273d0880cb";

            // refresh token
            await SAFE_RefreshToken(processId, credentialID, clientName);

            credentialID = await SAFE_ListCredential(processId, clientName);
        }

        Thread.Sleep(1000);

        var algo = await SAFE_InfoCredentials(credentialID, processId, clientName);

        Thread.Sleep(1000);

        await SAFE_Authorize(hashes, documentNames, credentialID, processId, clientName);

        Thread.Sleep(1000);

        var sad = await SAFE_VerifyAuth(processId);

        Thread.Sleep(1000);

        await SAFE_SignHash(sad, hashes, credentialID, processId, clientName, algo);

        Thread.Sleep(1000);

        var signedHash = await SAFE_VerifyHash(processId);

        // after loading the hash, create the file with the signed hash returned from the service
        client.CreatePdfSigned(signedHash, destEmpty, destSigned);
    }
    public static async Task SAFE_Info()
    {
        var response = await client.Info();

        Console.WriteLine("Description: {0}", response.Description);
        Console.WriteLine("Name: {0}", response.Name);
        Console.WriteLine("Region: {0}", response.Region);
        Console.WriteLine("Lang: {0}", response.Lang);
        Console.WriteLine("Specs: {0}", response.Specs);
        Console.WriteLine("Logo: {0}", response.Logo);

        Console.WriteLine("Methods:");
        foreach (var item in response.Methods)
        {
            Console.WriteLine($"\t{item}");
        }

        Console.WriteLine("AuthType:");
        foreach (var item in response.AuthType)
        {
            Console.WriteLine($"\t{item}");
        }
    }

    private static async Task SAFE_RefreshToken(string processId, string credentialID, string clientName)
    {
        var body = new UpdateTokenRequestDto
        {
            CredentialID = credentialID,
            ClientData = new ClientDataRequestBaseDto
            {
                ClientName = clientName,
                ProcessId = processId
            }
        };

        var response = await client.UpdateToken(body);

        Console.WriteLine("NewAccessToken: {0}", response.NewAccessToken);
        Console.WriteLine("NewRefreshToken: {0}", response.NewRefreshToken);

        client.UpdateTokens(response.NewAccessToken, response.NewRefreshToken);
    }

    private static async Task<string> SAFE_ListCredential(string processId, string clientName)
    {
        var body = new CredentialsListRequestDto
        {
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = processId,
                ClientName = clientName
            }
        };

        var response = await client.ListCredential(body);

        Console.WriteLine("CredentialIDs:");
        foreach (var item in response.CredentialIDs)
        {
            Console.WriteLine($"\t{item}");
        }

        return response.CredentialIDs.FirstOrDefault();
    }

    private static async Task<string> SAFE_InfoCredentials(string credentialID, string processId, string clientName)
    {
        var body = new CredentialsInfoRequestDto
        {
            Certificates = "chain",
            CredentialID = credentialID,
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = processId,
                ClientName = clientName
            }
        };

        Console.WriteLine("Call with CredentialID: {0}", body.CredentialID);
        Console.WriteLine("Call with ProcessId: {0}", body.ClientData.ProcessId);

        var response = await client.InfoCredentials(body);

        Console.WriteLine("AuthMode: {0}", response.AuthMode);
        Console.WriteLine("Multisign: {0}", response.Multisign);
        Console.WriteLine("Key Algo: {0}", response.Key.Algo);
        Console.WriteLine("Key Len: {0}", response.Key.Len);
        Console.WriteLine("Key Status: {0}", response.Key.Status);

        Console.WriteLine("Certificates:");
        int certNumber = 1;
        foreach (var cert in response.Cert.Certificates)
        {
            Console.WriteLine($"\t{cert}");

            var path = Path.Combine(@"E:\Faturação eletronica\Assinatura eletronica SAFE\tests", $"cert{certNumber}.der");

            if (File.Exists(path) == false)
                File.WriteAllBytes(path, Convert.FromBase64String(cert));

            certNumber++;
        }

        return response.Key.Algo;
    }

    private static async Task SAFE_Authorize(string[] hashes, string[] documentNames, string credentialID, string processId, string clientName)
    {
        var body = new SignHashAuthorizationRequestDto
        {
            CredentialID = credentialID,
            NumSignatures = documentNames.Length,
            ClientData = new SignHashAuthorizationClientDataRequestDto
            {
                ProcessId = processId,
                ClientName = clientName,
                DocumentNames = documentNames
            },
            Hashes = hashes
        };

        await client.Authorize(body);
    }

    private static async Task<string> SAFE_VerifyAuth(string processId)
    {
        var response = await client.VerifyAuth(processId);

        Console.WriteLine("SAD: {0}", response.Sad);

        return response.Sad;
    }

    private static async Task SAFE_SignHash(string sad, string[] hashes, string credentialID, string processId, string clientName, string algo)
    {
        var body = new SignHashRequestDto
        {
            Sad = sad,
            CredentialID = credentialID,
            SignAlgo = algo,
            ClientData = new ClientDataRequestBaseDto
            {
                ProcessId = processId,
                ClientName = clientName,
            },
            Hashes = hashes
        };

        Console.WriteLine("ProcessId: {0}", body.ClientData.ProcessId);
        await client.SignHash(body);
    }

    private static async Task<string> SAFE_VerifyHash(string processId)
    {
        var response = await client.VerifyHash(processId);

        Console.WriteLine("Signatures:");
        foreach (var item in response.Signatures)
        {
            Console.WriteLine(item);
        }

        return response.Signatures.FirstOrDefault();
    }
}