<a name='assembly'></a>
# SAFE2

## Contents

- [DocumentSign](#T-SAFE-DocumentSign 'SAFE.DocumentSign')
  - [BuildAuthUrl(configFolder,nif,email,info,redirectUri,testMode)](#M-SAFE-DocumentSign-BuildAuthUrl-System-String,System-String,System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.BuildAuthUrl(System.String,System.String,System.String,System.String,System.String,System.Boolean)')
  - [CancelAccount(configFolder,password,testMode)](#M-SAFE-DocumentSign-CancelAccount-System-String,System-String,System-Boolean- 'SAFE.DocumentSign.CancelAccount(System.String,System.String,System.Boolean)')
  - [CancelAccountAsync(configFolder,password,testMode)](#M-SAFE-DocumentSign-CancelAccountAsync-System-String,System-String,System-Boolean- 'SAFE.DocumentSign.CancelAccountAsync(System.String,System.String,System.Boolean)')
  - [CreateAccountAsync(configFolder,url,password,testMode)](#M-SAFE-DocumentSign-CreateAccountAsync-System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.CreateAccountAsync(System.String,System.String,System.String,System.Boolean)')
  - [GetAuth(configFolder)](#M-SAFE-DocumentSign-GetAuth-System-String- 'SAFE.DocumentSign.GetAuth(System.String)')
  - [GetCredentials(configFolder,password)](#M-SAFE-DocumentSign-GetCredentials-System-String,System-String- 'SAFE.DocumentSign.GetCredentials(System.String,System.String)')
  - [GetSignature(configFolder)](#M-SAFE-DocumentSign-GetSignature-System-String- 'SAFE.DocumentSign.GetSignature(System.String)')
  - [SignDocument(configFolder,pdfPath,password,testMode)](#M-SAFE-DocumentSign-SignDocument-System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.SignDocument(System.String,System.String,System.String,System.Boolean)')
  - [SignDocumentAsync(configFolder,pdfPath,password,testMode)](#M-SAFE-DocumentSign-SignDocumentAsync-System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.SignDocumentAsync(System.String,System.String,System.String,System.Boolean)')
  - [UpdateAuth(configFolder,clientName,clientId,username,password)](#M-SAFE-DocumentSign-UpdateAuth-System-String,System-String,System-String,System-String,System-String- 'SAFE.DocumentSign.UpdateAuth(System.String,System.String,System.String,System.String,System.String)')
  - [UpdateCredentials(configFolder,credentialID,accessToken,refreshToken,password)](#M-SAFE-DocumentSign-UpdateCredentials-System-String,System-String,System-String,System-String,System-String- 'SAFE.DocumentSign.UpdateCredentials(System.String,System.String,System.String,System.String,System.String)')
  - [UpdateSignature(configFolder,contactInfo,locationInfo,reason,timeStampServer,enableLtv,signatureX,signatureY,signatureWidth,signatureHeight,signatureImage)](#M-SAFE-DocumentSign-UpdateSignature-System-String,System-String,System-String,System-String,System-String,System-Boolean,System-Single,System-Single,System-Single,System-Single,System-String- 'SAFE.DocumentSign.UpdateSignature(System.String,System.String,System.String,System.String,System.String,System.Boolean,System.Single,System.Single,System.Single,System.Single,System.String)')
- [EncryptionHelpers](#T-SolRIA-SAFE-EncryptionHelpers 'SolRIA.SAFE.EncryptionHelpers')
  - [Decrypt(cipherText,keyString)](#M-SolRIA-SAFE-EncryptionHelpers-Decrypt-System-String,System-String- 'SolRIA.SAFE.EncryptionHelpers.Decrypt(System.String,System.String)')
  - [Encrypt(text,keyString)](#M-SolRIA-SAFE-EncryptionHelpers-Encrypt-System-String,System-String- 'SolRIA.SAFE.EncryptionHelpers.Encrypt(System.String,System.String)')
- [ExternalSigner](#T-SAFE-SAFE_Connect-ExternalSigner 'SAFE.SAFE_Connect.ExternalSigner')
- [LogService](#T-SolRIA-SAFE2-LogService 'SolRIA.SAFE2.LogService')
  - [Log(message)](#M-SolRIA-SAFE2-LogService-Log-System-String- 'SolRIA.SAFE2.LogService.Log(System.String)')
  - [Log(exception)](#M-SolRIA-SAFE2-LogService-Log-System-Exception- 'SolRIA.SAFE2.LogService.Log(System.Exception)')
- [SAFE_Connect](#T-SAFE-SAFE_Connect 'SAFE.SAFE_Connect')
  - [#ctor(httpClient,httpClientOauth)](#M-SAFE-SAFE_Connect-#ctor-System-Net-Http-HttpClient,System-Net-Http-HttpClient- 'SAFE.SAFE_Connect.#ctor(System.Net.Http.HttpClient,System.Net.Http.HttpClient)')
  - [Authorize()](#M-SAFE-SAFE_Connect-Authorize-SolRIA-SAFE-Models-SignHashAuthorizationRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.Authorize(SolRIA.SAFE.Models.SignHashAuthorizationRequestDto,SolRIA.SAFE.Models.Config)')
  - [Authorize()](#M-SAFE-SAFE_Connect-Authorize-SolRIA-SAFE-Models-SignHashAuthorizationRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.Authorize(SolRIA.SAFE.Models.SignHashAuthorizationRequestDto,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [CalculateHash(message)](#M-SAFE-SAFE_Connect-CalculateHash-System-Byte[]- 'SAFE.SAFE_Connect.CalculateHash(System.Byte[])')
  - [CancelAccount()](#M-SAFE-SAFE_Connect-CancelAccount-SolRIA-SAFE-Models-CancelCitizenAccountRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.CancelAccount(SolRIA.SAFE.Models.CancelCitizenAccountRequestDto,SolRIA.SAFE.Models.Config)')
  - [CancelAccount()](#M-SAFE-SAFE_Connect-CancelAccount-SolRIA-SAFE-Models-CancelCitizenAccountRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.CancelAccount(SolRIA.SAFE.Models.CancelCitizenAccountRequestDto,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [CreateAccountUrl(creationRequest,redirectUri)](#M-SAFE-SAFE_Connect-CreateAccountUrl-SolRIA-SAFE-Models-AccountCreationRequest,System-String- 'SAFE.SAFE_Connect.CreateAccountUrl(SolRIA.SAFE.Models.AccountCreationRequest,System.String)')
  - [CreatePdfEmptySignature(documentStream,inputFileStream,certificates,signatureConfig)](#M-SAFE-SAFE_Connect-CreatePdfEmptySignature-System-IO-Stream,System-IO-Stream,System-Collections-Generic-IList{System-Security-Cryptography-X509Certificates-X509Certificate2},SolRIA-SAFE-Models-SignatureConfig- 'SAFE.SAFE_Connect.CreatePdfEmptySignature(System.IO.Stream,System.IO.Stream,System.Collections.Generic.IList{System.Security.Cryptography.X509Certificates.X509Certificate2},SolRIA.SAFE.Models.SignatureConfig)')
  - [CreatePdfSigned(signedHash,inputFileStream,outputFileStream,certificates)](#M-SAFE-SAFE_Connect-CreatePdfSigned-System-String,System-IO-Stream,System-IO-Stream,System-Collections-Generic-IList{System-Security-Cryptography-X509Certificates-X509Certificate2}- 'SAFE.SAFE_Connect.CreatePdfSigned(System.String,System.IO.Stream,System.IO.Stream,System.Collections.Generic.IList{System.Security.Cryptography.X509Certificates.X509Certificate2})')
  - [Info()](#M-SAFE-SAFE_Connect-Info-SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.Info(SolRIA.SAFE.Models.Config)')
  - [Info()](#M-SAFE-SAFE_Connect-Info-SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.Info(SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [InfoCredentials()](#M-SAFE-SAFE_Connect-InfoCredentials-SolRIA-SAFE-Models-CredentialsInfoRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.InfoCredentials(SolRIA.SAFE.Models.CredentialsInfoRequestDto,SolRIA.SAFE.Models.Config)')
  - [InfoCredentials()](#M-SAFE-SAFE_Connect-InfoCredentials-SolRIA-SAFE-Models-CredentialsInfoRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.InfoCredentials(SolRIA.SAFE.Models.CredentialsInfoRequestDto,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [Init(auth)](#M-SAFE-SAFE_Connect-Init-SolRIA-SAFE-Models-BasicAuth- 'SAFE.SAFE_Connect.Init(SolRIA.SAFE.Models.BasicAuth)')
  - [ListCredential()](#M-SAFE-SAFE_Connect-ListCredential-SolRIA-SAFE-Models-CredentialsListRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.ListCredential(SolRIA.SAFE.Models.CredentialsListRequestDto,SolRIA.SAFE.Models.Config)')
  - [ListCredential()](#M-SAFE-SAFE_Connect-ListCredential-SolRIA-SAFE-Models-CredentialsListRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.ListCredential(SolRIA.SAFE.Models.CredentialsListRequestDto,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [ParseOauthResult(url)](#M-SAFE-SAFE_Connect-ParseOauthResult-System-String- 'SAFE.SAFE_Connect.ParseOauthResult(System.String)')
  - [ReadAccount(attribute)](#M-SAFE-SAFE_Connect-ReadAccount-SolRIA-SAFE-Models-AttributeManagerResult- 'SAFE.SAFE_Connect.ReadAccount(SolRIA.SAFE.Models.AttributeManagerResult)')
  - [SendCreateAccountRequest(token)](#M-SAFE-SAFE_Connect-SendCreateAccountRequest-System-String- 'SAFE.SAFE_Connect.SendCreateAccountRequest(System.String)')
  - [SignHash()](#M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.SignHash(SolRIA.SAFE.Models.SignHashRequestDto,SolRIA.SAFE.Models.Config)')
  - [SignHash(body,config,cancellationToken)](#M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.SignHash(SolRIA.SAFE.Models.SignHashRequestDto,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [UpdateToken()](#M-SAFE-SAFE_Connect-UpdateToken-SolRIA-SAFE-Models-UpdateTokenRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.UpdateToken(SolRIA.SAFE.Models.UpdateTokenRequestDto,SolRIA.SAFE.Models.Config)')
  - [UpdateToken()](#M-SAFE-SAFE_Connect-UpdateToken-SolRIA-SAFE-Models-UpdateTokenRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.UpdateToken(SolRIA.SAFE.Models.UpdateTokenRequestDto,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [VerifyAuth()](#M-SAFE-SAFE_Connect-VerifyAuth-System-String,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.VerifyAuth(System.String,SolRIA.SAFE.Models.Config)')
  - [VerifyAuth()](#M-SAFE-SAFE_Connect-VerifyAuth-System-String,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.VerifyAuth(System.String,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
  - [VerifyHash()](#M-SAFE-SAFE_Connect-VerifyHash-System-String,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.VerifyHash(System.String,SolRIA.SAFE.Models.Config)')
  - [VerifyHash()](#M-SAFE-SAFE_Connect-VerifyHash-System-String,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken- 'SAFE.SAFE_Connect.VerifyHash(System.String,SolRIA.SAFE.Models.Config,System.Threading.CancellationToken)')
- [SignEmpty](#T-SAFE-SAFE_Connect-SignEmpty 'SAFE.SAFE_Connect.SignEmpty')

<a name='T-SAFE-DocumentSign'></a>
## DocumentSign `type`

##### Namespace

SAFE

##### Summary



<a name='M-SAFE-DocumentSign-BuildAuthUrl-System-String,System-String,System-String,System-String,System-String,System-Boolean-'></a>
### BuildAuthUrl(configFolder,nif,email,info,redirectUri,testMode) `method`

##### Summary

Cria url para autenticação

##### Returns

Endereço com todos os parâmetros para criar a conta

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| nif | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | NIF usado para criar a conta |
| email | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Email que fica associado a conta |
| info | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Informações adicionais associadas a conta |
| redirectUri | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Endereço invocado pelo serviço SAFE com o resultado da criação da conta |
| testMode | [System.Boolean](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Boolean 'System.Boolean') | Usado ligar ao servidor de testes |

<a name='M-SAFE-DocumentSign-CancelAccount-System-String,System-String,System-Boolean-'></a>
### CancelAccount(configFolder,password,testMode) `method`

##### Summary

Cancela a conta previamente criada

##### Returns

Resultado do pedido

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Password usada na encriptação dos tokens de acesso ao serviço SAFE |
| testMode | [System.Boolean](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Boolean 'System.Boolean') | Usado ligar ao servidor de testes |

<a name='M-SAFE-DocumentSign-CancelAccountAsync-System-String,System-String,System-Boolean-'></a>
### CancelAccountAsync(configFolder,password,testMode) `method`

##### Summary

Versão assíncrona do método [CancelAccount](#M-SAFE-DocumentSign-CancelAccount-System-String,System-String,System-Boolean- 'SAFE.DocumentSign.CancelAccount(System.String,System.String,System.Boolean)')

##### Returns

Resultado do pedido

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Password usada na encriptação dos tokens de acesso ao serviço SAFE |
| testMode | [System.Boolean](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Boolean 'System.Boolean') | Usado ligar ao servidor de testes |

<a name='M-SAFE-DocumentSign-CreateAccountAsync-System-String,System-String,System-String,System-Boolean-'></a>
### CreateAccountAsync(configFolder,url,password,testMode) `method`

##### Summary

Lê o endereço devolvido pelo serviço SAFE depois de o utilizador ter feito a autenticação com sucesso e 
de ter sido feito o pedido de criação da conta usando o url criado com o método [BuildAuthUrl](#M-SAFE-DocumentSign-BuildAuthUrl-System-String,System-String,System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.BuildAuthUrl(System.String,System.String,System.String,System.String,System.String,System.Boolean)')

##### Returns

Resultado da criação da conta no serviço SAFE

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| url | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Url devolvido pelo serviço SAFE |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Password que vai encriptar os tokens de acesso ao serviço |
| testMode | [System.Boolean](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Boolean 'System.Boolean') | Usado ligar ao servidor de testes |

<a name='M-SAFE-DocumentSign-GetAuth-System-String-'></a>
### GetAuth(configFolder) `method`

##### Summary

Devolve as credenciais guardadas no ficheiro de configuração

##### Returns

Objecto com as credenciais fornecidas pelo serviço SAFE

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |

<a name='M-SAFE-DocumentSign-GetCredentials-System-String,System-String-'></a>
### GetCredentials(configFolder,password) `method`

##### Summary

Devolve as credenciais da conta de assinatura no SAFE guardadas no ficheiro de configuração

##### Returns

Objeto com as credenciais da conta de assinatura

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') |  |

<a name='M-SAFE-DocumentSign-GetSignature-System-String-'></a>
### GetSignature(configFolder) `method`

##### Summary

Obtém as informações guardadas no ficheiro de configuração sobre a assinatura digital pelo método [UpdateSignature](#M-SAFE-DocumentSign-UpdateSignature-System-String,System-String,System-String,System-String,System-String,System-Boolean,System-Single,System-Single,System-Single,System-Single,System-String- 'SAFE.DocumentSign.UpdateSignature(System.String,System.String,System.String,System.String,System.String,System.Boolean,System.Single,System.Single,System.Single,System.Single,System.String)')

##### Returns

Objeto com as informações da assinatura

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |

<a name='M-SAFE-DocumentSign-SignDocument-System-String,System-String,System-String,System-Boolean-'></a>
### SignDocument(configFolder,pdfPath,password,testMode) `method`

##### Summary

Assina digitalmente um documento PDF usando o serviço SAFE com as credenciais gravadas previamente

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| pdfPath | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho para o ficheiro PDF que deve ser assinado digitalmente |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Password usada na encriptação dos tokens de acesso ao serviço SAFE |
| testMode | [System.Boolean](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Boolean 'System.Boolean') | Usado ligar ao servidor de testes |

<a name='M-SAFE-DocumentSign-SignDocumentAsync-System-String,System-String,System-String,System-Boolean-'></a>
### SignDocumentAsync(configFolder,pdfPath,password,testMode) `method`

##### Summary

Versão assíncrona do método [SignDocument](#M-SAFE-DocumentSign-SignDocument-System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.SignDocument(System.String,System.String,System.String,System.Boolean)')

##### Returns



##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') |  |
| pdfPath | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') |  |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') |  |
| testMode | [System.Boolean](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Boolean 'System.Boolean') |  |

<a name='M-SAFE-DocumentSign-UpdateAuth-System-String,System-String,System-String,System-String,System-String-'></a>
### UpdateAuth(configFolder,clientName,clientId,username,password) `method`

##### Summary

Grava as credenciais no ficheiro de configuração da SW que foi previamente autorizada pelo serviço SAFE. 
Estas credenciais serão utilizadas posteriormente para invocar os serviços SAFE como [SignDocument](#M-SAFE-DocumentSign-SignDocument-System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.SignDocument(System.String,System.String,System.String,System.Boolean)')

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| clientName | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Nome do cliente, fornecido pelo serviço SAFE |
| clientId | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Id do cliente, fornecido pelo serviço SAFE |
| username | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Utilizador, fornecido pelo serviço SAFE |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Password, fornecido pelo serviço SAFE |

<a name='M-SAFE-DocumentSign-UpdateCredentials-System-String,System-String,System-String,System-String,System-String-'></a>
### UpdateCredentials(configFolder,credentialID,accessToken,refreshToken,password) `method`

##### Summary

Grava as credenciais da conta de assinatura criada no SAFE, no ficheiro de configuração.

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| credentialID | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | O ID, criado pelo serviço SAFE na criação da conta |
| accessToken | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Token de acesso, criado pelo serviço SAFE na criação da conta |
| refreshToken | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Token de refresh usado quando o `accessToken` está expirado, criado pelo serviço SAFE na criação da conta |
| password | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Password que vai encriptar os tokens `accessToken` e `refreshToken` |

<a name='M-SAFE-DocumentSign-UpdateSignature-System-String,System-String,System-String,System-String,System-String,System-Boolean,System-Single,System-Single,System-Single,System-Single,System-String-'></a>
### UpdateSignature(configFolder,contactInfo,locationInfo,reason,timeStampServer,enableLtv,signatureX,signatureY,signatureWidth,signatureHeight,signatureImage) `method`

##### Summary

Guarda os dados usados para criar a assinatura digital no documento PDF.
Esta informação será utilizada no momento de assinatura no método [SignDocument](#M-SAFE-DocumentSign-SignDocument-System-String,System-String,System-String,System-Boolean- 'SAFE.DocumentSign.SignDocument(System.String,System.String,System.String,System.Boolean)')

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| configFolder | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho da pasta que contém o ficheiro de configuração |
| contactInfo | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Informação do contato que ficará na assinatura digital |
| locationInfo | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Informação da localização que ficará na assinatura digital |
| reason | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Informação da razão da assinatura que ficará na assinatura digital |
| timeStampServer | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Endereço do servidor temporal, caso se queira criar uma assinatura com validação temporal |
| enableLtv | [System.Boolean](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Boolean 'System.Boolean') | Flag que ativa o parâmetro LTV na assinatura digital |
| signatureX | [System.Single](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Single 'System.Single') | Coordenada x para a posição da imagem da assinatura começando pelo canto superior esquerdo do documento |
| signatureY | [System.Single](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Single 'System.Single') | Coordenada y para a posição da imagem da assinatura começando pelo canto superior esquerdo do documento |
| signatureWidth | [System.Single](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Single 'System.Single') | Largura da imagem da assinatura |
| signatureHeight | [System.Single](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Single 'System.Single') | Altura da imagem da assinatura |
| signatureImage | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Caminho para a imagem a ser utilizada como visual da assinatura eletrónica |

<a name='T-SolRIA-SAFE-EncryptionHelpers'></a>
## EncryptionHelpers `type`

##### Namespace

SolRIA.SAFE

##### Summary

Helpers para encriptar e ler dados encriptados

<a name='M-SolRIA-SAFE-EncryptionHelpers-Decrypt-System-String,System-String-'></a>
### Decrypt(cipherText,keyString) `method`

##### Summary

Lê o texto encriptado `cipherText` com a pass `keyString`

##### Returns

Texto descodificado

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| cipherText | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Texto encriptado |
| keyString | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Pass usada para encriptar o texto no método [Encrypt](#M-SolRIA-SAFE-EncryptionHelpers-Encrypt-System-String,System-String- 'SolRIA.SAFE.EncryptionHelpers.Encrypt(System.String,System.String)') |

<a name='M-SolRIA-SAFE-EncryptionHelpers-Encrypt-System-String,System-String-'></a>
### Encrypt(text,keyString) `method`

##### Summary

Encripta o `text` com a pass `keyString` usando o método AES

##### Returns

Texto encriptado

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| text | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Texto a encriptar |
| keyString | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | pass para encriptar o `text` |

<a name='T-SAFE-SAFE_Connect-ExternalSigner'></a>
## ExternalSigner `type`

##### Namespace

SAFE.SAFE_Connect

##### Summary

Represents to replace an empty signature from an external signer.

<a name='T-SolRIA-SAFE2-LogService'></a>
## LogService `type`

##### Namespace

SolRIA.SAFE2

##### Summary

Log Helper

<a name='M-SolRIA-SAFE2-LogService-Log-System-String-'></a>
### Log(message) `method`

##### Summary

Log a message to the log file

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| message | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | The message to log |

<a name='M-SolRIA-SAFE2-LogService-Log-System-Exception-'></a>
### Log(exception) `method`

##### Summary

Log exception details to the log file

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| exception | [System.Exception](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Exception 'System.Exception') | The exception to log |

<a name='T-SAFE-SAFE_Connect'></a>
## SAFE_Connect `type`

##### Namespace

SAFE

##### Summary

Classe com vários métodos de acesso ao serviço SAFE

<a name='M-SAFE-SAFE_Connect-#ctor-System-Net-Http-HttpClient,System-Net-Http-HttpClient-'></a>
### #ctor(httpClient,httpClientOauth) `constructor`

##### Summary



##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| httpClient | [System.Net.Http.HttpClient](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Net.Http.HttpClient 'System.Net.Http.HttpClient') | Cliente http para aceder a API de assinatura dos documentos do serviço SAFE |
| httpClientOauth | [System.Net.Http.HttpClient](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Net.Http.HttpClient 'System.Net.Http.HttpClient') | Cliente http para aceder a API de autenticação do serviço AMA |

<a name='M-SAFE-SAFE_Connect-Authorize-SolRIA-SAFE-Models-SignHashAuthorizationRequestDto,SolRIA-SAFE-Models-Config-'></a>
### Authorize() `method`

##### Summary

Método que pede autorização para efetuar uma assinatura. 
Neste método, o Software de Faturação deve gerar a(s) hash(es) do(s) documento(s) a assinar, 
o SAFE regista a(s) hash(es) a assinar e gera um Signature Activation Data (SAD)
que terá de ser enviado pelo Software de Faturação no pedido de assinatura [SignHash](#M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.SignHash(SolRIA.SAFE.Models.SignHashRequestDto,SolRIA.SAFE.Models.Config)'). 
Um SAD é único para cada pedido assinatura.

##### Returns

Mensagem de erro caso a operação não seja bem sucedida ou string vazio em caso de sucesso

##### Parameters

This method has no parameters.

##### Exceptions

| Name | Description |
| ---- | ----------- |
| [SolRIA.SAFE.Models.ApiException](#T-SolRIA-SAFE-Models-ApiException 'SolRIA.SAFE.Models.ApiException') | Exceoção com os detalhes da resposta do serviço SAFE |

<a name='M-SAFE-SAFE_Connect-Authorize-SolRIA-SAFE-Models-SignHashAuthorizationRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### Authorize() `method`

##### Summary

Versão assíncrona do método [Authorize](#M-SAFE-SAFE_Connect-Authorize-SolRIA-SAFE-Models-SignHashAuthorizationRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.Authorize(SolRIA.SAFE.Models.SignHashAuthorizationRequestDto,SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-CalculateHash-System-Byte[]-'></a>
### CalculateHash(message) `method`

##### Summary

Converte a hash para o formato requerido pelo SAFE

##### Returns



##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| message | [System.Byte[]](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Byte[] 'System.Byte[]') |  |

<a name='M-SAFE-SAFE_Connect-CancelAccount-SolRIA-SAFE-Models-CancelCitizenAccountRequestDto,SolRIA-SAFE-Models-Config-'></a>
### CancelAccount() `method`

##### Summary

Método que permite o cancelamento de uma conta de assinatura.

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-CancelAccount-SolRIA-SAFE-Models-CancelCitizenAccountRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### CancelAccount() `method`

##### Summary

Versão assíncrona do método [CancelAccount](#M-SAFE-SAFE_Connect-CancelAccount-SolRIA-SAFE-Models-CancelCitizenAccountRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.CancelAccount(SolRIA.SAFE.Models.CancelCitizenAccountRequestDto,SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-CreateAccountUrl-SolRIA-SAFE-Models-AccountCreationRequest,System-String-'></a>
### CreateAccountUrl(creationRequest,redirectUri) `method`

##### Summary

Método que gera o url que será usado no pedido oauth

##### Returns

Url usado no pedido de autenticação oauth

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| creationRequest | [SolRIA.SAFE.Models.AccountCreationRequest](#T-SolRIA-SAFE-Models-AccountCreationRequest 'SolRIA.SAFE.Models.AccountCreationRequest') | Parametros usados na criação da conta do cliente |
| redirectUri | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Endereço invocado pelo serviço SAFE com as credenciais ou mensagem de erro |

<a name='M-SAFE-SAFE_Connect-CreatePdfEmptySignature-System-IO-Stream,System-IO-Stream,System-Collections-Generic-IList{System-Security-Cryptography-X509Certificates-X509Certificate2},SolRIA-SAFE-Models-SignatureConfig-'></a>
### CreatePdfEmptySignature(documentStream,inputFileStream,certificates,signatureConfig) `method`

##### Summary

Cria uma assinatura vazia no ficheiro PDF e devolve o hash resultante para a assinatura digital externa

##### Returns

Hash do documento a assinar pelo serviço externo

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| documentStream | [System.IO.Stream](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.IO.Stream 'System.IO.Stream') | Stream do ficheiro PDF a assinar |
| inputFileStream | [System.IO.Stream](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.IO.Stream 'System.IO.Stream') | Stream do ficheiro PDF que vai conter a assinatura |
| certificates | [System.Collections.Generic.IList{System.Security.Cryptography.X509Certificates.X509Certificate2}](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Collections.Generic.IList 'System.Collections.Generic.IList{System.Security.Cryptography.X509Certificates.X509Certificate2}') | Lista com os certificados usados na assinatura digital |
| signatureConfig | [SolRIA.SAFE.Models.SignatureConfig](#T-SolRIA-SAFE-Models-SignatureConfig 'SolRIA.SAFE.Models.SignatureConfig') | A configuração da assinatura |

<a name='M-SAFE-SAFE_Connect-CreatePdfSigned-System-String,System-IO-Stream,System-IO-Stream,System-Collections-Generic-IList{System-Security-Cryptography-X509Certificates-X509Certificate2}-'></a>
### CreatePdfSigned(signedHash,inputFileStream,outputFileStream,certificates) `method`

##### Summary

Insere a hash assinada pelo serviço externo no ficheiro a assinar digitalmente

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| signedHash | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | A hash assinada |
| inputFileStream | [System.IO.Stream](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.IO.Stream 'System.IO.Stream') | Stream do ficheiro PDF a assinar |
| outputFileStream | [System.IO.Stream](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.IO.Stream 'System.IO.Stream') | Stream do ficheiro PDF que vai conter a assinatura |
| certificates | [System.Collections.Generic.IList{System.Security.Cryptography.X509Certificates.X509Certificate2}](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Collections.Generic.IList 'System.Collections.Generic.IList{System.Security.Cryptography.X509Certificates.X509Certificate2}') | Lista com os certificados usados na assinatura digital |

<a name='M-SAFE-SAFE_Connect-Info-SolRIA-SAFE-Models-Config-'></a>
### Info() `method`

##### Summary

Método que retorna informação sobre o serviço e a lista de todos os métodos implementados.

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-Info-SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### Info() `method`

##### Summary

Versão assíncrona do método [Info](#M-SAFE-SAFE_Connect-Info-SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.Info(SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-InfoCredentials-SolRIA-SAFE-Models-CredentialsInfoRequestDto,SolRIA-SAFE-Models-Config-'></a>
### InfoCredentials() `method`

##### Summary

Método que retorna a informação associada a uma conta de assinatura. 
Nomeadamente, informação sobre o estado da conta de assinatura e a 
cadeia de certificados associados à conta de assinatura. 
A cadeia de certificados deve ser utilizada para construir os documentos assinados 
associadas à conta de assinatura.

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-InfoCredentials-SolRIA-SAFE-Models-CredentialsInfoRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### InfoCredentials() `method`

##### Summary

Versão assíncrona do método [InfoCredentials](#M-SAFE-SAFE_Connect-InfoCredentials-SolRIA-SAFE-Models-CredentialsInfoRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.InfoCredentials(SolRIA.SAFE.Models.CredentialsInfoRequestDto,SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-Init-SolRIA-SAFE-Models-BasicAuth-'></a>
### Init(auth) `method`

##### Summary

Inicializa as credenciais da SW fornecidas pelo SAFE

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| auth | [SolRIA.SAFE.Models.BasicAuth](#T-SolRIA-SAFE-Models-BasicAuth 'SolRIA.SAFE.Models.BasicAuth') | Credenciais |

<a name='M-SAFE-SAFE_Connect-ListCredential-SolRIA-SAFE-Models-CredentialsListRequestDto,SolRIA-SAFE-Models-Config-'></a>
### ListCredential() `method`

##### Summary

Método que retorna a lista de credenciais associados a uma conta de assinatura. 
Cada conta de assinatura do SAFE tem apenas uma credencial, 
que deve ser enviada em todos os métodos que requeiram o parâmetro credentialId

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-ListCredential-SolRIA-SAFE-Models-CredentialsListRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### ListCredential() `method`

##### Summary

Versão assíncrona do método [ListCredential](#M-SAFE-SAFE_Connect-ListCredential-SolRIA-SAFE-Models-CredentialsListRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.ListCredential(SolRIA.SAFE.Models.CredentialsListRequestDto,SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-ParseOauthResult-System-String-'></a>
### ParseOauthResult(url) `method`

##### Summary

Lê o `url` enviado pelo serviço SAFE e verifica a existência de erros e caso existam lê as credenciais

##### Returns



##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| url | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | Url de retorno criado pelo serviço SAFE com as credenciais pedidas ou mensagem de erro |

<a name='M-SAFE-SAFE_Connect-ReadAccount-SolRIA-SAFE-Models-AttributeManagerResult-'></a>
### ReadAccount(attribute) `method`

##### Summary

Método que envia o pedido de credenciais da conta criada pelo oauth

##### Returns

Tokens de autenticação no serviço de assinatura

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| attribute | [SolRIA.SAFE.Models.AttributeManagerResult](#T-SolRIA-SAFE-Models-AttributeManagerResult 'SolRIA.SAFE.Models.AttributeManagerResult') | Tokens de autenticação recebidos no pedido de criação de conta [SendCreateAccountRequest](#M-SAFE-SAFE_Connect-SendCreateAccountRequest-System-String- 'SAFE.SAFE_Connect.SendCreateAccountRequest(System.String)') |

<a name='M-SAFE-SAFE_Connect-SendCreateAccountRequest-System-String-'></a>
### SendCreateAccountRequest(token) `method`

##### Summary

Método que envia o pedido de criação de conta para assinatura da FA

##### Returns

Credenciais de autenticação usados no pedido de leitura da conta [ReadAccount](#M-SAFE-SAFE_Connect-ReadAccount-SolRIA-SAFE-Models-AttributeManagerResult- 'SAFE.SAFE_Connect.ReadAccount(SolRIA.SAFE.Models.AttributeManagerResult)')

##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| token | [System.String](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.String 'System.String') | access_token enviado pela autenticação oauth |

<a name='M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config-'></a>
### SignHash() `method`

##### Summary

Método que pede assinatura de hash(es). 
Este método que deve ser invocado após a invocação do método de verificação de autorização [VerifyAuth](#M-SAFE-SAFE_Connect-VerifyAuth-System-String,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.VerifyAuth(System.String,SolRIA.SAFE.Models.Config)'),
verifica se o SAD recebido corresponde ao que foi gerado no método de autorização, e assina a(s) hash(es) assinada(s).

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### SignHash(body,config,cancellationToken) `method`

##### Summary



##### Returns



##### Parameters

| Name | Type | Description |
| ---- | ---- | ----------- |
| body | [SolRIA.SAFE.Models.SignHashRequestDto](#T-SolRIA-SAFE-Models-SignHashRequestDto 'SolRIA.SAFE.Models.SignHashRequestDto') |  |
| config | [SolRIA.SAFE.Models.Config](#T-SolRIA-SAFE-Models-Config 'SolRIA.SAFE.Models.Config') |  |
| cancellationToken | [System.Threading.CancellationToken](http://msdn.microsoft.com/query/dev14.query?appId=Dev14IDEF1&l=EN-US&k=k:System.Threading.CancellationToken 'System.Threading.CancellationToken') |  |

##### Exceptions

| Name | Description |
| ---- | ----------- |
| [SolRIA.SAFE.Models.ApiException](#T-SolRIA-SAFE-Models-ApiException 'SolRIA.SAFE.Models.ApiException') |  |

<a name='M-SAFE-SAFE_Connect-UpdateToken-SolRIA-SAFE-Models-UpdateTokenRequestDto,SolRIA-SAFE-Models-Config-'></a>
### UpdateToken() `method`

##### Summary

Método que retorna um novo AccessToken e um novo RefreshToken para uma conta de assinatura. 
Estes novos tokens devem ser utilizados nas invocações futuras aos serviços. 
Este método deve ser invocado sempre que o sistema retorne o erro HTTP 400 Bad Request, 
com a mensagem de erro “The access or refresh token is expired or has been revoked”

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-UpdateToken-SolRIA-SAFE-Models-UpdateTokenRequestDto,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### UpdateToken() `method`

##### Summary

Versão assíncrona do método [UpdateToken](#M-SAFE-SAFE_Connect-UpdateToken-SolRIA-SAFE-Models-UpdateTokenRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.UpdateToken(SolRIA.SAFE.Models.UpdateTokenRequestDto,SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-VerifyAuth-System-String,SolRIA-SAFE-Models-Config-'></a>
### VerifyAuth() `method`

##### Summary

Método que verifica autorização para efetuar uma assinatura.
Neste método, o Software de Faturação deve enviar o processId utilizado na invocação do método
de pedido de autorização [Authorize](#M-SAFE-SAFE_Connect-Authorize-SolRIA-SAFE-Models-SignHashAuthorizationRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.Authorize(SolRIA.SAFE.Models.SignHashAuthorizationRequestDto,SolRIA.SAFE.Models.Config)'). 
O SAFE devolve o Signature Activation Data (SAD) que terá de ser enviado pelo Software
de Faturação no pedido de assinatura [SignHash](#M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.SignHash(SolRIA.SAFE.Models.SignHashRequestDto,SolRIA.SAFE.Models.Config)').
Um SAD é único para cada pedido assinatura. 
Este método deve ser invocado do seguinte modo: 
A primeira invocação deve ser feita 1 segundo após a invocação do método de pedido de autorização [Authorize](#M-SAFE-SAFE_Connect-Authorize-SolRIA-SAFE-Models-SignHashAuthorizationRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.Authorize(SolRIA.SAFE.Models.SignHashAuthorizationRequestDto,SolRIA.SAFE.Models.Config)').
Se o SAFE devolver um código HTTP 204 No Content (ou seja, não devolver o SAD), 
o pedido deve ser repetido mais 4 vezes (total de 5 vezes), com intervalos de 1 segundo.

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-VerifyAuth-System-String,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### VerifyAuth() `method`

##### Summary

Versão assíncrono do método [VerifyHash](#M-SAFE-SAFE_Connect-VerifyHash-System-String,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.VerifyHash(System.String,SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-VerifyHash-System-String,SolRIA-SAFE-Models-Config-'></a>
### VerifyHash() `method`

##### Summary

Método que retorna a(s) hash(es) assinada(s). 
Este método deve ser invocado após a invocação do método de pedido de assinatura autorização
[SignHash](#M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.SignHash(SolRIA.SAFE.Models.SignHashRequestDto,SolRIA.SAFE.Models.Config)').
O Software de Faturação deve enviar o processId utilizado na invocação do método de pedido de assinatura
[SignHash](#M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.SignHash(SolRIA.SAFE.Models.SignHashRequestDto,SolRIA.SAFE.Models.Config)') e o SAFE verifica se a assinatura já foi efetuada. 
Se sim, o SAFE devolve a(s) hash(es) assinada(s). 
Neste passo, o Software de Faturação deve construir o documento assinado, juntando, ao documento original, 
a hash assinada do documento e os certificados obtidos no método credentials/info [Info](#M-SAFE-SAFE_Connect-Info-SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.Info(SolRIA.SAFE.Models.Config)'). 
Este método deve ser invocado do seguinte modo: 
a primeira invocação deve ser feita 1 segundo após a invocação do método de pedido de assinatura [SignHash](#M-SAFE-SAFE_Connect-SignHash-SolRIA-SAFE-Models-SignHashRequestDto,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.SignHash(SolRIA.SAFE.Models.SignHashRequestDto,SolRIA.SAFE.Models.Config)').
Se o SAFE devolver um código HTTP 204 No Content (ou seja, não devolver a(s) hash(es) assinada(s)) 
o pedido deve ser repetido mais 4 vezes (num total de 5 vezes), com intervalos de 1 segundo.

##### Parameters

This method has no parameters.

<a name='M-SAFE-SAFE_Connect-VerifyHash-System-String,SolRIA-SAFE-Models-Config,System-Threading-CancellationToken-'></a>
### VerifyHash() `method`

##### Summary

Versão assíncrona do método [VerifyHash](#M-SAFE-SAFE_Connect-VerifyHash-System-String,SolRIA-SAFE-Models-Config- 'SAFE.SAFE_Connect.VerifyHash(System.String,SolRIA.SAFE.Models.Config)')

##### Parameters

This method has no parameters.

<a name='T-SAFE-SAFE_Connect-SignEmpty'></a>
## SignEmpty `type`

##### Namespace

SAFE.SAFE_Connect

##### Summary

Represents to sign an empty signature from the external signer.
