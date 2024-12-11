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
    private readonly string _targetService;
    public LdapAuthOptions Options { get; set; }

    public NtlmAuthenticationHandler(string targetService, ILogger logger = null)
    {
        _logger = logger ?? Logging.LogProvider.CreateLogger("NtlmAuthenticationHandler");
        _targetService = targetService;

        Options = new LdapAuthOptions()
        {
            Signing = false,
            Bindings = null
        };
    }

    public async Task<object> PerformNtlmAuthenticationAsync(INtlmTransport transport)
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

        // CHALLENGE
        var challengeMessageBytes = await transport.NegotiateAsync(negotiateMsgBytes);

        // AUTHENTICATE
        var authenticateMsgBytes = context.Step(challengeMessageBytes);

        // Perform final authentication
        var response = await transport.AuthenticateAsync(authenticateMsgBytes);

        return response;
    }
}
