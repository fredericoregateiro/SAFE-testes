namespace SAFE;

public static class TestsSAFE
{
    public static readonly string src = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\FT23-68.pdf";
    public static readonly string destEmpty = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\FT23-68-empty.pdf";
    public static readonly string destSigned = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\FT23-68-signed.pdf";

    public static async Task SignDocument()
    {
        // create a pdf with empty signature
        var initialHash = SAFE_Sign.CreatePdfEmptySignature(src, destEmpty);

        // calculate the has of the pdf document with a empty signature
        var hashes = new string[]
        {
            SAFE_Sign.CalculateHash(initialHash),
        };

        // get the original filename
        var documentNames = new string[] { Path.GetFileName(src) };

        // client name is set by the SAFE team
        var clientName = "clientTest";

        // processId must be unique to one sign session
        var processId = Guid.NewGuid().ToString();

        // build the http client used for all comunications
        var httpClient = new HttpClient();

        //TODO: the credential should be save o on the config for this client
        string credentialID;

        try
        {
            credentialID = await SAFE_ListCredential(processId, clientName, httpClient);
        }
        catch (SolRIA.Sign.SAFE.Models.ApiException ex) when
            (ex.StatusCode is System.Net.HttpStatusCode.Unauthorized or System.Net.HttpStatusCode.BadRequest)
        {
            credentialID = "b63db1b2-b6e6-4124-8842-a0273d0880cb";

            // refresh token
            await SAFE_RefreshToken(processId, credentialID, clientName, httpClient);

            credentialID = await SAFE_ListCredential(processId, clientName, httpClient);
        }

        Thread.Sleep(1000);

        var algo = await SAFE_InfoCredentials(credentialID, processId, clientName, httpClient);

        Thread.Sleep(1000);

        await SAFE_Authorize(hashes, documentNames, credentialID, processId, clientName, httpClient);

        Thread.Sleep(1000);

        var sad = await SAFE_VerifyAuth(processId, httpClient);

        Thread.Sleep(1000);

        await SAFE_SignHash(sad, hashes, credentialID, processId, clientName, algo, httpClient);

        Thread.Sleep(1000);

        var signedHash = await SAFE_VerifyHash(processId, httpClient);

        // after loading the hash, create the file with the signed hash returned from the service
        SAFE_Sign.CreatePdfSigned(signedHash, destEmpty, destSigned);
    }
    public static async Task SAFE_Info(HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var response = await client.Info(httpClient);

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

    public static async Task SAFE_RefreshToken(string processId, string credentialID, string clientName, HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var body = new SolRIA.Sign.SAFE.Models.UpdateTokenRequestDto
        {
            CredentialID = credentialID,
            ClientData = new SolRIA.Sign.SAFE.Models.ClientDataRequestBaseDto
            {
                ClientName = clientName,
                ProcessId = processId
            }
        };

        var response = await client.UpdateToken(body, httpClient);

        Console.WriteLine("NewAccessToken: {0}", response.NewAccessToken);
        Console.WriteLine("NewRefreshToken: {0}", response.NewRefreshToken);

        client.UpdateAccessToken(response.NewAccessToken);
        client.UpdateRefreshToken(response.NewRefreshToken);
    }

    private static async Task<string> SAFE_ListCredential(string processId, string clientName, HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var body = new SolRIA.Sign.SAFE.Models.CredentialsListRequestDto
        {
            ClientData = new SolRIA.Sign.SAFE.Models.ClientDataRequestBaseDto
            {
                ProcessId = processId,
                ClientName = clientName
            }
        };

        var response = await client.ListCredential(body, httpClient);

        Console.WriteLine("CredentialIDs:");
        foreach (var item in response.CredentialIDs)
        {
            Console.WriteLine($"\t{item}");
        }

        return response.CredentialIDs.FirstOrDefault();
    }

    private static async Task<string> SAFE_InfoCredentials(string credentialID, string processId, string clientName, HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var body = new SolRIA.Sign.SAFE.Models.CredentialsInfoRequestDto
        {
            Certificates = "chain",
            CredentialID = credentialID,
            ClientData = new SolRIA.Sign.SAFE.Models.ClientDataRequestBaseDto
            {
                ProcessId = processId,
                ClientName = clientName
            }
        };

        Console.WriteLine("Call with CredentialID: {0}", body.CredentialID);
        Console.WriteLine("Call with ProcessId: {0}", body.ClientData.ProcessId);

        var response = await client.InfoCredentials(body, httpClient);

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

    private static async Task SAFE_Authorize(string[] hashes, string[] documentNames, string credentialID, string processId, string clientName, HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var body = new SolRIA.Sign.SAFE.Models.SignHashAuthorizationRequestDto
        {
            CredentialID = credentialID,
            NumSignatures = documentNames.Length,
            ClientData = new SolRIA.Sign.SAFE.Models.SignHashAuthorizationClientDataRequestDto
            {
                ProcessId = processId,
                ClientName = clientName,
                DocumentNames = documentNames
            },
            Hashes = hashes
        };

        await client.Authorize(body, httpClient);
    }

    private static async Task<string> SAFE_VerifyAuth(string processId, HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var response = await client.VerifyAuth(processId, httpClient);

        Console.WriteLine("SAD: {0}", response.Sad);

        return response.Sad;
    }

    private static async Task SAFE_SignHash(string sad, string[] hashes, string credentialID, string processId, string clientName, string algo, HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var body = new SolRIA.Sign.SAFE.Models.SignHashRequestDto
        {
            Sad = sad,
            CredentialID = credentialID,
            SignAlgo = algo,
            ClientData = new SolRIA.Sign.SAFE.Models.ClientDataRequestBaseDto
            {
                ProcessId = processId,
                ClientName = clientName,
            },
            Hashes = hashes
        };

        Console.WriteLine("ProcessId: {0}", body.ClientData.ProcessId);
        await client.SignHash(body, httpClient);
    }

    private static async Task<string> SAFE_VerifyHash(string processId, HttpClient httpClient)
    {
        var client = new SAFE_Connect();

        var response = await client.VerifyHash(processId, httpClient);

        Console.WriteLine("Signatures:");
        foreach (var item in response.Signatures)
        {
            Console.WriteLine(item);
        }

        return response.Signatures.FirstOrDefault();
    }
}