namespace SolRIA.Sign.SAFE.Models;

public sealed class Certificate
{
    public int Id { get; set; }
    public int Order { get; set; }
    public byte[] CertificateData { get; set; }
}