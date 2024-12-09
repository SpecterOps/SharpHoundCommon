using System;
using System.Net;
using System.Net.Http;

namespace SharpHoundCommonLib.Ntlm;

public interface IHttpClientFactory
{
    HttpClient CreateUnauthenticatedClient();
    HttpClient CreateAuthenticatedHttpClient(Uri Url, string authPackage = "Kerberos");
}

public class HttpClientFactory : IHttpClientFactory
{
    public HttpClient CreateUnauthenticatedClient()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) => true,
            UseDefaultCredentials = false
        };

        return new HttpClient(handler);
    }

    public HttpClient CreateAuthenticatedHttpClient(Uri Url, string authPackage = "Kerberos")
    {
        var handler = new HttpClientHandler
        {
            Credentials = new CredentialCache()
            {
                { Url, authPackage, CredentialCache.DefaultNetworkCredentials }
            },

            PreAuthenticate = true,
            ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) =>
                {
                    return true;
                },
        };

        return new HttpClient(handler);
    }
}
