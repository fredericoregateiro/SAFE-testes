<template>
  <q-page class="flex flex-center">
    <q-btn @click="login" label="LOGIN CMD" size="xl" color="primary"/>
  </q-page>
</template>

<script>
import { defineComponent } from 'vue'

export default defineComponent({
  name: 'IndexPage',
  setup () {
    const login = () => {
      // get the authorizationUrl and redirectUrl from the server
      // redirect_uri=http://127.0.0.1:9000/safe&
      const authorizationUrl = "https://preprod.autenticacao.gov.pt//oauth/askauthorization?redirect_uri=https://faturas.solria.pt/safe&client_id=7880823882782159029&scope=http://interop.gov.pt/MDC/Cidadao/NIC%20http://interop.gov.pt/MDC/Cidadao/NomeProprio%20http://interop.gov.pt/MDC/Cidadao/NomeApelido%20http://interop.gov.pt/MDC/Cidadao/DataNascimento%20http://interop.gov.pt/MDC/Cidadao/NIF%20http://interop.gov.pt/SAFE/createSignatureAccount?enterpriseNipc=510958362$enterpriseAdditionalInfo=erp$email=suporte@solria.pt$expirationDate=2023-12-18$signaturesLimit=450000$creationClientName=clientTest&response_type=token";
      //const redirectUrl = "/Authorized#";

      const authWindow = window.open(authorizationUrl, '_blank');

      // const checkInterval = setInterval(function () {
			// 	if (authWindow.location.href.includes(redirectUrl)) {
			// 		clearInterval(checkInterval);
			// 		// The user has finished the authorization process.
			// 		// Extract the authorization code from the URL and close the popup window.
      //     console.log(authWindow.location.href)
			// 		let url = new URL(authWindow.location.href);
			// 		let access_token = url.searchParams.get("access_token");
			// 		authWindow.close();

      //     console.log(access_token);
			// 	}
			// }, 1000);
    }

    return {
      login
    }
  }
})
</script>
