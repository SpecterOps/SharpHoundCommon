using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

public class HttpTransport : INtlmTransport
{
    private readonly ILogger _logger;
    private readonly HttpClient _httpClient;
    private readonly Uri _url;
    private readonly string _authScheme;

    public HttpTransport(HttpClient httpClient, Uri url, string authScheme, ILogger logger = null)
    {
        _logger = logger ?? Logging.LogProvider.CreateLogger(nameof(HttpTransport));
        _httpClient = httpClient;
        _url = url;
        _authScheme = authScheme;
    }

    public async Task<byte[]> NegotiateAsync(byte[] negotiateMessage)
    {
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, _url);
        var messageBase64 = Convert.ToBase64String(negotiateMessage);
        requestMessage.Headers.Add("Authorization", $"{_authScheme} {messageBase64}");

        var response = await _httpClient.SendAsync(requestMessage);

        if (!response.Headers.Contains("WWW-Authenticate"))
        {
            throw new InvalidOperationException("No WWW-Authenticate header found in response");
        }

        var authHeaders = response.Headers.WwwAuthenticate.Where(a => a.Scheme == _authScheme).ToArray();
        if (!authHeaders.Any())
        {
            throw new InvalidOperationException($"No WWW-Authenticate header found in response. Auth Scheme: {_authScheme}");
        }

        var challengeMessageB64 = authHeaders.First().Parameter;
        if (challengeMessageB64 == null)
        {
            throw new MissingChallengeException($"No challenge received from the server. Auth Scheme: {_authScheme}");
        }

        return Convert.FromBase64String(challengeMessageB64);
    }

    public async Task<Object> AuthenticateAsync(byte[] authenticateMessage)
    {
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, _url);
        var messageBase64 = Convert.ToBase64String(authenticateMessage);
        requestMessage.Headers.Add("Authorization", $"{_authScheme} {messageBase64}");

        var response = await _httpClient.SendAsync(requestMessage);
        return response;
    }
}

public class MissingChallengeException : Exception
{
    public MissingChallengeException(string message): base(message)
    {
    }
}

