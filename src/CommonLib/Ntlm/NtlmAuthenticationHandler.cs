using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Processors;
using SharpHoundCommonLib.ThirdParty.PSOpenAD;
using System.Threading;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

interface INtlmAuthenticationHandler {
    Task<object> PerformNtlmAuthenticationAsync(INtlmTransport transport, CancellationToken cancellationToken = default);
}

/// <summary>
/// Uses an implementation of transports to actually perform the NTLM authentication. 
/// </summary>
public class NtlmAuthenticationHandler : INtlmAuthenticationHandler {
    private readonly ILogger _logger;
    private readonly string _targetService;
    public LdapAuthOptions Options { get; set; }

    public NtlmAuthenticationHandler(string targetService, ILogger logger = null) {
        _logger = logger ?? Logging.LogProvider.CreateLogger("NtlmAuthenticationHandler");
        _targetService = targetService;

        Options = new LdapAuthOptions {
            Signing = false,
            Bindings = null
        };
    }

    public virtual async Task<object> PerformNtlmAuthenticationAsync(INtlmTransport transport, CancellationToken cancellationToken = default) {
        using var context = new SspiContext(
            null,
            null,
            AuthenticationMethod.NTLM,
            _targetService,
            Options.Bindings,
            Options.Signing,
            Options.Signing
        );

        cancellationToken.ThrowIfCancellationRequested();

        // NEGOTIATE
        var negotiateMsgBytes = context.Step();

        // CHALLENGE
        var challengeMessageBytes = await transport.NegotiateAsync(negotiateMsgBytes);

        cancellationToken.ThrowIfCancellationRequested();

        // AUTHENTICATE
        var authenticateMsgBytes = context.Step(challengeMessageBytes);

        // Perform final authentication
        var response = await transport.AuthenticateAsync(authenticateMsgBytes);

        return response;
    }
}