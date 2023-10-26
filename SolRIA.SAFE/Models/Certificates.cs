namespace SolRIA.Sign.SAFE.Models;

public sealed class Certificates
{
    public int Id { get; set; }
    public int Order { get; set; }
    public byte[] CertificateData { get; set; }
}