using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Syncfusion.Drawing;
using Syncfusion.Pdf.Parsing;
using Syncfusion.Pdf.Security;

namespace SAFE;

public class SAFE_Sign
{
    //TODO: save the certificates on secure location
    private static readonly string certFile1 = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\cert1.der";
    private static readonly string certFile2 = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\cert2.der";
    private static readonly string certFile3 = @"E:\Faturação eletronica\Assinatura eletronica SAFE\tests\cert3.der";

    public static byte[] CreatePdfEmptySignature(string filename, string emptyPdfSignature)
    {
        //Get the stream from a document.
        using var documentStream = new FileStream(filename, FileMode.Open, FileAccess.Read);

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
        var certificates = new List<X509Certificate2>
        {
            LoadCertificate(certFile1),
            LoadCertificate(certFile2),
            LoadCertificate(certFile3)
        };
        signature.AddExternalSigner(emptySignature, certificates, null);

        using var inputFileStream = new FileStream(emptyPdfSignature, FileMode.Create, FileAccess.ReadWrite);
        loadedDocument.Save(inputFileStream);

        //Close the PDF document.
        loadedDocument.Close(true);

        return emptySignature.Message;
    }
    public static void CreatePdfSigned(string signedHash, string emptyPdfSignature, string outputFile)
    {
        //Create an external signer with a signed hash message.
        var externalSigner = new ExternalSigner(signedHash);

        //Add public certificates.
        var certificates = new List<X509Certificate2>
        {
            LoadCertificate(certFile1),
            LoadCertificate(certFile2),
            LoadCertificate(certFile3)
        };

        // create an output file stream that will be the signed document
        using var outputFileStream = new FileStream(outputFile, FileMode.Create, FileAccess.ReadWrite);

        // get the stream from the document with the empty signature
        using var inputFileStream = new FileStream(emptyPdfSignature, FileMode.Open, FileAccess.Read);

        string pdfPassword = string.Empty;

        // replace an empty signature.
        PdfSignature.ReplaceEmptySignature(inputFileStream, pdfPassword, outputFileStream, "Signature", externalSigner, certificates, true);
    }

    private static X509Certificate2 LoadCertificate(string filename)
    {
        //Creates a certificate instance from PFX file with private key
        var certificateStream = new FileStream(filename, FileMode.Open, FileAccess.Read);
        byte[] data = new byte[certificateStream.Length];
        certificateStream.Read(data, 0, data.Length);

        //Create new X509Certificate2 with the root certificate
        return new X509Certificate2(data);
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

    public static string CalculateHash(string filename)
    {
        // openssl sha256 -binary in.pdf > out.txt
        // openssl base64 -in out.txt -out out64.txt

        byte[] sha256SigPrefix = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

        using var SHA256 = System.Security.Cryptography.SHA256.Create();
        using FileStream fileStream = File.OpenRead(filename);

        var fileHashArray = SHA256.ComputeHash(fileStream);

        return Convert.ToBase64String(sha256SigPrefix.Concat(fileHashArray).ToArray());
    }

    public static string CalculateHash(byte[] message)
    {
        byte[] sha256SigPrefix = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

        message = SHA256.HashData(message);

        return Convert.ToBase64String(sha256SigPrefix.Concat(message).ToArray());
    }
}