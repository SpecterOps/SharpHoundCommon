using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;

namespace SharpHoundCommonLib.Ntlm;

public interface INtlmHttpClientFactory {
    HttpClient CreateUnauthenticatedClient();
    HttpClient CreateAuthenticatedHttpClient(Uri Url, string authPackage = "Kerberos");
}

public class NtlmHttpClientFactory : INtlmHttpClientFactory {
    private readonly SslProtocols _sslProtocols;

    /// <summary>
    /// Creates an HttpClientFactory whose handlers will negotiate TLS using OS/framework defaults.
    /// </summary>
    public NtlmHttpClientFactory() : this(SslProtocols.None) { }

    /// <summary>
    /// Creates an HttpClientFactory whose handlers will restrict TLS negotiation to the specified protocols.
    /// Use this overload when a specific set of legacy protocols must be supported for a target service,
    /// rather than setting <see cref="System.Net.ServicePointManager.SecurityProtocol"/> process-wide.
    /// </summary>
    /// <param name="sslProtocols">
    /// The SSL/TLS protocols to allow. Pass <see cref="SslProtocols.None"/> to defer to OS/framework defaults.
    /// </param>
    public NtlmHttpClientFactory(SslProtocols sslProtocols) {
        _sslProtocols = sslProtocols;
    }

    public HttpClient CreateUnauthenticatedClient() {
        var handler = new HttpClientHandler {
            ServerCertificateCustomValidationCallback = 
                (httpRequestMessage, cert, cetChain, policyErrors) => true,
            UseDefaultCredentials = false
        };

        if (_sslProtocols != SslProtocols.None)
            handler.SslProtocols = _sslProtocols;

        return new HttpClient(handler);
    }

    public HttpClient CreateAuthenticatedHttpClient(Uri Url, string authPackage = "Kerberos") {
        var handler = new HttpClientHandler {
            Credentials = new CredentialCache() {
                { Url, authPackage, CredentialCache.DefaultNetworkCredentials }
            },

            PreAuthenticate = true,
            ServerCertificateCustomValidationCallback =
                (httpRequestMessage, cert, cetChain, policyErrors) => true,
        };

        if (_sslProtocols != SslProtocols.None)
            handler.SslProtocols = _sslProtocols;

        return new HttpClient(handler);
    }
}