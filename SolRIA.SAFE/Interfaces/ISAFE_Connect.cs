using SolRIA.SAFE.Models;
using SolRIA.Sign.SAFE.Models;
using System.Security.Cryptography.X509Certificates;

namespace SolRIA.Sign.SAFE.Interfaces;

public interface ISAFE_Connect
{
    void Init(BasicAuth auth);

    string CreateAccountUrl(AccountCreationRequest creationRequest);
    MessageResult ParseOauthResult(string url);
    Task<AttributeManagerResult> SendCreateAccountRequest(string token);
    Task<AccountCreationResult> ReadAccount(AttributeManagerResult attribute);

    Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, Config config);
    Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, Config config, CancellationToken cancellationToken);

    Task<string> CancelAccount(CancelCitizenAccountRequestDto body, Config config);
    Task<string> CancelAccount(CancelCitizenAccountRequestDto body, Config config, CancellationToken cancellationToken);

    Task<InfoResponseDto> Info(Config config);
    Task<InfoResponseDto> Info(Config config, CancellationToken cancellationToken);

    Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, Config config);
    Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, Config config, CancellationToken cancellationToken);

    Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, Config config);
    Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, Config config, CancellationToken cancellationToken);

    Task<string> Authorize(SignHashAuthorizationRequestDto body, Config config);
    Task<string> Authorize(SignHashAuthorizationRequestDto body, Config config, CancellationToken cancellationToken);

    Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, Config config);
    Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, Config config, CancellationToken cancellationToken);

    Task<string> SignHash(SignHashRequestDto body, Config config);
    Task<string> SignHash(SignHashRequestDto body, Config config, CancellationToken cancellationToken);

    Task<SignHashResponseDto> VerifyHash(string processId, Config config);
    Task<SignHashResponseDto> VerifyHash(string processId, Config config, CancellationToken cancellationToken);

    byte[] CreatePdfEmptySignature(Stream documentStream, Stream inputFileStream, IList<X509Certificate2> certificates, SignatureConfig signatureConfig);
    void CreatePdfSigned(string signedHash, Stream inputFileStream, Stream outputFileStream, IList<X509Certificate2> certificates);
    string CalculateHash(byte[] message);
}