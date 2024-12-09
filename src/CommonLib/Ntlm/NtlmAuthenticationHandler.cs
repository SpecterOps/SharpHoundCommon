using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Processors;
using SharpHoundCommonLib.ThirdParty.PSOpenAD;
using System;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

interface INtlmAuthenticationHandler
{
    Task<object> PerformNtlmAuthenticationAsync(INtlmTransport transport);
}

public class NtlmAuthenticationHandler : INtlmAuthenticationHandler
{
    private readonly ILogger _logger;
    private readonly string _host;
    private readonly string _targetService;
    private const string NtlmAuthPackageName = "NTLM";
    public LdapAuthOptions Options { get; set; }

    public NtlmAuthenticationHandler(ILogger logger, string host, string targetService)
    {
        _logger = logger;
        _host = host;
        _targetService = targetService;

        Options = new LdapAuthOptions()
        {
            Signing = false,
            Bindings = null
        };
    }

    public async Task<Object> PerformNtlmAuthenticationAsync(INtlmTransport transport)
    {
        using var context = new SspiContext(
                null,
                null,
                AuthenticationMethod.NTLM,
                _targetService,
                Options.Bindings,
                Options.Signing,
                Options.Signing
            );

        // NEGOTIATE
        var negotiateMsgBytes = context.Step();
        //_logger.LogDebug($"NTLM-NEGOTIATE message: {Convert.ToBase64String(negotiateMsgBytes)}");

        // CHALLENGE
        var challengeMessageBytes = await transport.NegotiateAsync(negotiateMsgBytes);
        //_logger.LogDebug($"NTLM-CHALLENGE message: {Convert.ToBase64String(challengeMessageBytes)}");

        // AUTHENTICATE
        var authenticateMsgBytes = context.Step(challengeMessageBytes);
        //_logger.LogDebug($"NTLM-AUTHENTICATE message: {Convert.ToBase64String(authenticateMsgBytes)}");

        // Perform final authentication
        var response = await transport.AuthenticateAsync(authenticateMsgBytes);

        return response;
    }
}
