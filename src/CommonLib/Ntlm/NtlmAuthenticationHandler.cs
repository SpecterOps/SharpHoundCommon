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
        _logger.LogTrace("Starting {MethodName}", nameof(PerformNtlmAuthenticationAsync));

        _logger.LogTrace("Check if cancellation token is requested.");
        cancellationToken.ThrowIfCancellationRequested();
        _logger.LogTrace("After if cancellation token is requested.");

        // NEGOTIATE
        _logger.LogDebug("Initial NTLM Negotiate Step.");
        var negotiateMsgBytes = context.Step();
        _logger.LogTrace("Negotiate Step Complete.");

        // CHALLENGE
        _logger.LogDebug("Challenge Negotiate bytes.");
        var challengeMessageBytes = await transport.NegotiateAsync(negotiateMsgBytes);
        _logger.LogTrace("Challenge Negotiate bytes complete.");

        _logger.LogTrace("Check if cancellation token is requested.");
        cancellationToken.ThrowIfCancellationRequested();
        _logger.LogTrace("After if cancellation token is requested.");

        // AUTHENTICATE
        _logger.LogDebug("Perform NTLM Authentication Step.");
        var authenticateMsgBytes = context.Step(challengeMessageBytes);
        _logger.LogTrace("NTLM Authentication Step Complete.");

        // Perform final authentication
        _logger.LogDebug("Perform final NTLM Authentication.");
        var response = await transport.AuthenticateAsync(authenticateMsgBytes);
        _logger.LogTrace("After authentication complete.");

        return response;
    }
}