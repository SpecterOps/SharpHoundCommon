using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

/// <summary>
/// This has been implemented as a bespoke service in order to allow us to change channel bindings. This is not possible with the built in NTLM functions
/// This service uses HTTP to authenticate over NTLM to computers. During the authentication process you can specify channel binding settings which is important
/// for our workflow.
/// </summary>
public class HttpNtlmAuthenticationService {
    private readonly ILogger _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly AdaptiveTimeout _getSupportedNTLMAuthSchemesAdaptiveTimeout;
    private readonly AdaptiveTimeout _ntlmAuthAdaptiveTimeout;
    private readonly AdaptiveTimeout _authWithChannelBindingAdaptiveTimeout;

    public HttpNtlmAuthenticationService(IHttpClientFactory httpClientFactory, ILogger logger = null) {
        _logger = logger ?? Logging.LogProvider.CreateLogger(nameof(HttpNtlmAuthenticationService));
        _httpClientFactory = httpClientFactory;
        _getSupportedNTLMAuthSchemesAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger(nameof(GetSupportedNtlmAuthSchemesAsync)), sampleCount: 100, logFrequency: 1000, minSamplesForAdaptiveTimeout: 30);
        _ntlmAuthAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger(nameof(NtlmAuthenticationHandler.PerformNtlmAuthenticationAsync)), sampleCount: 100, logFrequency: 1000, minSamplesForAdaptiveTimeout: 30);
        _authWithChannelBindingAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger(nameof(AuthWithBadChannelBindingsAsync)), sampleCount: 100, logFrequency: 1000, minSamplesForAdaptiveTimeout: 30);
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
                await AuthWithBadChannelBindingsAsync(url, authScheme);
            } else {
                if ((bool)useBadChannelBindings) {
                    await AuthWithBadChannelBindingsAsync(url, authScheme);
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

        var result = await _getSupportedNTLMAuthSchemesAdaptiveTimeout.ExecuteWithTimeout(async (timeoutToken) => {
            var getResponse = await httpClient.SendAsync(getRequest, timeoutToken);
            return ExtractAuthSchemes(getResponse);
        });

        if (result.IsSuccess)
            return result.Value;
        else
            throw new TimeoutException($"Timeout getting supported NTLM auth schemes for {url}");
    }

    internal string[] ExtractAuthSchemes(HttpResponseMessage response) {
        if (response.StatusCode == HttpStatusCode.OK) {
            throw new AuthNotRequiredException(
                "Authorization was not solicited when enumerating Authentication schemes");
        }

        // We expect to get an Unauthorized. If not, something is off
        if (response.StatusCode != HttpStatusCode.Unauthorized) {
            if (response.StatusCode == HttpStatusCode.Forbidden) {
                throw new HttpForbiddenException("Forbidden when enumerating Auth schemes");
            }

            if (response.StatusCode == HttpStatusCode.InternalServerError) {
                throw new HttpServerErrorException("Server Error when enumerating Auth schemes");
            }

            // Use .NET's exceptions to make things easy
            response.EnsureSuccessStatusCode();
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

    private async Task AuthWithBadChannelBindingsAsync(Uri url, string authScheme, NtlmAuthenticationHandler ntlmAuth = null) {
        var httpClient = _httpClientFactory.CreateUnauthenticatedClient();
        var transport = new HttpTransport(httpClient, url, authScheme, _logger);
        var ntlmAuthHandler = ntlmAuth ?? new NtlmAuthenticationHandler($"HTTP/{url.Host}");

        var result = await _ntlmAuthAdaptiveTimeout.ExecuteWithTimeout((timeoutToken) => ntlmAuthHandler.PerformNtlmAuthenticationAsync(transport, timeoutToken));

        if (!result.IsSuccess) {
            throw new TimeoutException($"Timeout during NTLM authentication for {url} with {authScheme}");
        }

        var response = (HttpResponseMessage)result.Value;

        if (response.StatusCode == HttpStatusCode.OK) {
            return;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized) {
            throw new HttpUnauthorizedException(
                $"401 Unauthorized when accessing {url} with {authScheme} and no signing");
        }

        if (response.StatusCode == HttpStatusCode.Forbidden) {
            // Indicates the path exists but is inaccessible. 
            // Common cause: trying to access CES (which requires HTTPS by default) over HTTP
            throw new HttpForbiddenException($"403 Forbidden when accessing {url} with {authScheme} and no signing");
        }

        if (response.StatusCode == HttpStatusCode.InternalServerError) {
            var body = await response.Content.ReadAsStringAsync();
            if (body.Contains("ExtendedProtectionPolicy.PolicyEnforcement"))
                throw new ExtendedProtectionMisconfiguredException(
                    $"EPA misconfigured at {url} with {authScheme} and no signing");
        }

        response.EnsureSuccessStatusCode();
    }

    private async Task<bool> AuthWithChannelBindingAsync(Uri url, string authScheme) {
        var handler = new HttpClientHandler {
            ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErrors) => true,
        };

        var credentialCache = new CredentialCache {
            { url, authScheme, CredentialCache.DefaultNetworkCredentials }
        };

        handler.Credentials = credentialCache;
        handler.PreAuthenticate = true;

        using var client = new HttpClient(handler);

        var result = await _authWithChannelBindingAdaptiveTimeout.ExecuteWithTimeout(async (timeoutToken) => {
            try {
                HttpResponseMessage response = await client.GetAsync(url, timeoutToken);
                return response.StatusCode == HttpStatusCode.OK;
            }
            catch (AuthenticationException ex) {
                _logger.LogWarning(ex, $"Authentication failed for {url} with {authScheme}");
                return false;
            }
        });

        if (result.IsSuccess)
            return result.Value;
        else
            throw new TimeoutException($"Timeout during channel binding authentication for {url} with {authScheme}");
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
internal class ExtendedProtectionMisconfiguredException : Exception {
    public ExtendedProtectionMisconfiguredException() {
    }

    public ExtendedProtectionMisconfiguredException(string message) : base(message) {
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