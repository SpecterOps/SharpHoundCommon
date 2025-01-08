using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

public class HttpNtlmAuthenticationService {
    private readonly ILogger _logger;
    private readonly IHttpClientFactory _httpClientFactory;

    public HttpNtlmAuthenticationService(IHttpClientFactory httpClientFactory, ILogger logger = null) {
        _logger = logger ?? Logging.LogProvider.CreateLogger(nameof(HttpNtlmAuthenticationService));
        _httpClientFactory = httpClientFactory;
    }

    public async Task EnsureRequiresAuth(Uri url, bool? useBadChannelBindings) {
        if (url == null)
            throw new ArgumentException("Url property is null");

        if (useBadChannelBindings == null && url.Scheme == "https")
            throw new ArgumentException("When using HTTPS, useBadChannelBindings must be set");

        var supportedAuthSchemes = await GetSupportedNtlmAuthSchemesAsync(url);

        _logger.LogDebug($"Supported NTLM auth schemes for {url}: " + string.Join(",", supportedAuthSchemes));

        foreach (var authScheme in supportedAuthSchemes) {
            if (useBadChannelBindings == null) {
                await AuthWithBadChannelBindings(url, authScheme);
            } else {
                if ((bool)useBadChannelBindings) {
                    await AuthWithBadChannelBindings(url, authScheme);
                } else {
                    await AuthWithChannelBindingAsync(url, authScheme);
                }
            }

            // If we've got here, everything has worked and it's accessible, so return
            return;
        }
    }

    private async Task<string[]> GetSupportedNtlmAuthSchemesAsync(Uri url) {
        var httpClient = _httpClientFactory.CreateUnauthenticatedClient();

        using var getRequest = new HttpRequestMessage(HttpMethod.Get, url);
        using var getResponse = await httpClient.SendAsync(getRequest);
        return ExtractAuthSchemes(getResponse);
    }

    private string[] ExtractAuthSchemes(HttpResponseMessage response) {
        if (response.StatusCode == HttpStatusCode.OK) {
            throw new AuthNotRequiredException(
                "Authorization was not solicited when enumerating Authentication schemes");
        }

        // We expect to get an Unauthorized. If not, something is off
        if (response.StatusCode != HttpStatusCode.Unauthorized) {
            if (response.StatusCode == HttpStatusCode.Forbidden) {
                throw new HttpForbiddenException("Forbidden when enumerating Auth schemes");
            } else if (response.StatusCode == HttpStatusCode.InternalServerError) {
                throw new HttpServerErrorException("Server Error when enumerating Auth schemes");
            } else {
                // Use .NET's exceptions to make things easy
                response.EnsureSuccessStatusCode();
            }
        }

        if (response.Headers.WwwAuthenticate == null) {
            throw new InvalidOperationException("WWW-Authenticate header is missing");
        }

        var schemes = response.Headers.WwwAuthenticate
            .Select(header => header.Scheme)
            .Where(scheme => scheme == "NTLM" || scheme == "Negotiate")
            .Distinct()
            .ToArray();

        return schemes;
    }

    private async Task AuthWithBadChannelBindings(Uri url, string authScheme) {
        var httpClient = _httpClientFactory.CreateUnauthenticatedClient();
        var transport = new HttpTransport(httpClient, url, authScheme, _logger);
        var ntlmAuthHandler = new NtlmAuthenticationHandler($"HTTP/{url.Host}");

        var response = (HttpResponseMessage)await ntlmAuthHandler.PerformNtlmAuthenticationAsync(transport);

        if (response.StatusCode == HttpStatusCode.OK) {
            return;
        } else if (response.StatusCode == HttpStatusCode.Unauthorized) {
            throw new HttpUnauthorizedException(
                $"401 Unauthorized when accessing {url} with {authScheme} and no signing");
        } else if (response.StatusCode == HttpStatusCode.Forbidden) {
            throw new HttpForbiddenException($"403 Forbidden when accessing {url} with {authScheme} and no signing");
        }

        response.EnsureSuccessStatusCode();
    }

    private async Task<bool> AuthWithChannelBindingAsync(Uri url, string authScheme) {
        var handler = new HttpClientHandler {
            ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) => true,
        };

        var credentialCache = new CredentialCache();
        credentialCache.Add(url, authScheme, CredentialCache.DefaultNetworkCredentials);

        handler.Credentials = credentialCache;
        handler.PreAuthenticate = true;

        using var client = new HttpClient(handler);

        try {
            HttpResponseMessage response = await client.GetAsync(url);
            return response.StatusCode == HttpStatusCode.OK;
        } catch (AuthenticationException ex) {
            _logger.LogWarning(ex, $"Authentication failed for {url} with {authScheme}");
            return false;
        }
    }
}

[Serializable]
internal class HttpUnauthorizedException : Exception {
    public HttpUnauthorizedException() {
    }

    public HttpUnauthorizedException(string message) : base(message) {
    }
}

[Serializable]
internal class HttpForbiddenException : Exception {
    public HttpForbiddenException() {
    }

    public HttpForbiddenException(string message) : base(message) {
    }
}

[Serializable]
internal class HttpServerErrorException : Exception {
    public HttpServerErrorException() {
    }

    public HttpServerErrorException(string message) : base(message) {
    }
}

[Serializable]
internal class AuthNotRequiredException : Exception {
    public AuthNotRequiredException() {
    }

    public AuthNotRequiredException(string message) : base(message) {
    }
}