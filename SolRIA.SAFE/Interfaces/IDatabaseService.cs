using SolRIA.Sign.SAFE.Models;
using System.Security.Cryptography.X509Certificates;

namespace SolRIA.SAFE.Interfaces;

public interface IDatabaseService
{
    void Init();

    Config LoadConfig(string password);
    Config UpdateConfig(Config config, string password);

    SignatureConfig LoadSignatureConfig();
    void UpdateSignatureConfig(SignatureConfig signatureConfig);

    BasicAuth LoadBasicAuth();
    void UpdateBasicAuth(BasicAuth basicAuth);

    List<X509Certificate2> LoadCertificates();
    List<X509Certificate2> UpdateCertificates(IEnumerable<Certificate> certificates);
}
