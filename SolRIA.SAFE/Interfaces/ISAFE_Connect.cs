using SolRIA.Sign.SAFE.Models;

namespace SolRIA.Sign.SAFE.Interfaces;

public interface ISAFE_Connect
{
    void InitTokens();
    void UpdateTokens(string newAccessToken, string newRefreshToken);

    Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body);
    Task<UpdateTokenResponseDto> UpdateToken(UpdateTokenRequestDto body, CancellationToken cancellationToken);

    Task<string> CancelAccount(CancelCitizenAccountRequestDto body);
    Task<string> CancelAccount(CancelCitizenAccountRequestDto body, CancellationToken cancellationToken);

    Task<InfoResponseDto> Info();
    Task<InfoResponseDto> Info(CancellationToken cancellationToken);

    Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body);
    Task<CredentialsListResponseDto> ListCredential(CredentialsListRequestDto body, CancellationToken cancellationToken);

    Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body);
    Task<CredentialsInfoResponseDto> InfoCredentials(CredentialsInfoRequestDto body, CancellationToken cancellationToken);

    Task<string> Authorize(SignHashAuthorizationRequestDto body);
    Task<string> Authorize(SignHashAuthorizationRequestDto body, CancellationToken cancellationToken);

    Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId);
    Task<SignHashAuthorizationResponseDto> VerifyAuth(string processId, CancellationToken cancellationToken);

    Task<string> SignHash(SignHashRequestDto body);
    Task<string> SignHash(SignHashRequestDto body, CancellationToken cancellationToken);

    Task<SignHashResponseDto> VerifyHash(string processId);
    Task<SignHashResponseDto> VerifyHash(string processId, CancellationToken cancellationToken);

    byte[] CreatePdfEmptySignature(Stream documentStream, Stream inputFileStream);
    void CreatePdfSigned(string signedHash, string emptyPdfSignature, string outputFile);
    string CalculateHash(byte[] message);
}