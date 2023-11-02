# Criar conta manualmente

[ambiente de testes](https://pprwww.autenticacao.gov.pt/)

[ambiente de produção CMD](https://www.autenticacao.gov.pt/chave-movel-digital/autenticacao)

[ambiente de produção CC](https://www.autenticacao.gov.pt/cartao-cidadao/autenticacao)

# Criar conta OAuth

[ambiente produção](http://interop.gov.pt/SAFE/createSignatureAccount)

# Timestamp server

[servidor cartão cidadão](http://ts.cartaodecidadao.pt/tsa/server)

# Executar testes

```csharp

var folder = "caminho pasta que contêm a base de dados com a configuração";
var pdf = "caminho para o pdf a ser assinado";

await DocumentSign.SignDocument(folder, pdf);
```
