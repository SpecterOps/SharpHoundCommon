using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Ntlm;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.ThirdParty.PSOpenAD;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using SharpHoundRPC.PortScanner;
using System.Threading;

namespace SharpHoundCommonLib.Processors;

public class LdapAuthOptions {
    public bool Signing { get; set; }
    public ChannelBindings? Bindings { get; set; }
}

/// <summary>
/// This processor checks if LDAP is requiring signing, as well as if channel binding is disabled. This is only used for domain controllers
/// </summary>
public class DCLdapProcessor {
    private readonly ILogger _log;
    private readonly IPortScanner _scanner;
    private readonly int _ldapTimeout;
    private readonly Uri _ldapEndpoint;
    private readonly Uri _ldapSslEndpoint;
    private readonly AdaptiveTimeout _checkIsNtlmSigningRequiredAdaptiveTimeout;
    private readonly AdaptiveTimeout _checkIsChannelBindingDisabledAdaptiveTimeout;
    public delegate Task ComputerStatusDelegate(CSVComputerStatus status);

    private readonly string SEC_E_UNSUPPORTED_FUNCTION = "80090302";
    private readonly string SEC_E_BAD_BINDINGS = "80090346";


    public DCLdapProcessor(int connectionTimeoutMs, string dcHostname, ILogger log = null) {
        _log = log ?? Logging.LogProvider.CreateLogger("DCLdapProcessor");
        _scanner = new PortScanner(maxTimeout: connectionTimeoutMs);
        _ldapTimeout = connectionTimeoutMs / 1000;
        _ldapEndpoint = new Uri($"ldap://{dcHostname}:389");
        _ldapSslEndpoint = new Uri($"ldaps://{dcHostname}:636");
        _checkIsNtlmSigningRequiredAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(1), Logging.LogProvider.CreateLogger(nameof(CheckIsNtlmSigningRequired)));
        _checkIsChannelBindingDisabledAdaptiveTimeout = new AdaptiveTimeout(maxTimeout: TimeSpan.FromMinutes(1), Logging.LogProvider.CreateLogger(nameof(CheckIsChannelBindingDisabled)));
    }
    
    public event ComputerStatusDelegate ComputerStatusEvent;

    public async Task<LdapService> Scan(string computerName) {
        var hasLdap = await TestLdapPort();
        var hasLdaps = await TestLdapsPort();
        SharpHoundRPC.Result<bool> isSigningRequired = new(),
            isChannelBindingDisabled = new();

        if (hasLdap) {
            isSigningRequired = await _checkIsNtlmSigningRequiredAdaptiveTimeout.ExecuteRPCWithTimeout(CheckIsNtlmSigningRequired);
        }

        if (hasLdaps) {
            isChannelBindingDisabled = await _checkIsChannelBindingDisabledAdaptiveTimeout.ExecuteRPCWithTimeout(CheckIsChannelBindingDisabled);
        }

        if (isSigningRequired.IsFailed) {
            await SendComputerStatus(new CSVComputerStatus {
                Status = isSigningRequired.Error,
                Task = "DCLdapIsSigningRequired",
                ComputerName = computerName
            });
            _log.LogTrace("DCLdapScan failed on IsSigningRequired for {ComputerName}: {Status}", computerName, isSigningRequired.Status);
        } else {
            await SendComputerStatus(new CSVComputerStatus {
                Status = CSVComputerStatus.StatusSuccess,
                Task = "DCLdapIsSigningRequired",
                ComputerName = computerName
            });
        }

        if (isChannelBindingDisabled.IsFailed) {
            await SendComputerStatus(new CSVComputerStatus {
                Status = isChannelBindingDisabled.Error,
                Task = "DCLdapIsChannelBindingDisabled",
                ComputerName = computerName
            });
            _log.LogTrace("DCLdapScan failed on IsChannelBindingDisabled for {ComputerName}: {Status}", computerName, isSigningRequired.Status);
        } else {
            await SendComputerStatus(new CSVComputerStatus {
                Status = CSVComputerStatus.StatusSuccess,
                Task = "DCLdapIsChannelBindingDisabled",
                ComputerName = computerName
            });
        }
        
        return new LdapService(
            hasLdap,
            hasLdaps,
            new APIResult<bool>
            {
                Collected = isSigningRequired.IsSuccess,
                FailureReason = isSigningRequired.Error,
                Result = isSigningRequired.Value,

            },
            new APIResult<bool>
            {
                Collected = isChannelBindingDisabled.IsSuccess,
                FailureReason = isChannelBindingDisabled.Error,
                Result = isChannelBindingDisabled.Value,

            }
        );
    }

    /// <summary>
    /// Tests if the specified Ldap port is open
    /// </summary>
    /// <returns>bool</returns>
    [ExcludeFromCodeCoverage]
    public virtual async Task<bool> TestLdapPort() {
        return await _scanner.CheckPort(_ldapEndpoint.Host, _ldapEndpoint.Port);
    }

    [ExcludeFromCodeCoverage]
    public virtual async Task<bool> TestLdapsPort() {
        return await _scanner.CheckPort(_ldapSslEndpoint.Host, _ldapSslEndpoint.Port);
    }

    public async Task<SharpHoundRPC.Result<bool>> CheckIsNtlmSigningRequired(CancellationToken cancellationToken = default) {
        try {
            var options = new LdapAuthOptions() {
                Signing = false
            };
            var accessibleWithoutSigning = await Authenticate(_ldapEndpoint, options, cancellationToken : cancellationToken);

            return SharpHoundRPC.Result<bool>.Ok(accessibleWithoutSigning == false);

        } catch (Exception ex) {
            return SharpHoundRPC.Result<bool>.Fail($"CheckIsNtlmSigningRequired failed: {ex}");
        }
    }

    // Checks if EPA is enabled. Does so by trying to auth with wrong channel bindings.
    // If auth is successful despite the wrong bindings, then EPA is not required.
    // Note: Ideally we'd check if it works under 3 conditions:
    // 1) No channel bindings to check if configured to "Never"
    // 2) Invalid bindings to check if configured to "Always" (would error)
    // 3) Correct bindings to ensure NTLM auth is enabled
    // However, as of right now we only do #2. We can't do #1 right now since the
    // Window's SSPI APIs (InitSecurityContext) always add channel bindings.
    public async Task<SharpHoundRPC.Result<bool>> CheckIsChannelBindingDisabled(CancellationToken cancellationToken = default) {
        try {
            // 1) Can we connect with *invalid* bindings

            var bindings = new ChannelBindings {
                ApplicationData = [0, 0, 0, 0]
            };
            var accessibleWithNoBindings = await Authenticate(_ldapSslEndpoint, new LdapAuthOptions() {
                Signing = false,
                Bindings = bindings
            }, cancellationToken : cancellationToken);
            return SharpHoundRPC.Result<bool>.Ok(accessibleWithNoBindings);

        } catch (Exception ex) {
            return SharpHoundRPC.Result<bool>.Fail($"CheckIsNtlmSigningRequired failed: {ex}");
        }
    }

    /// <summary>
    /// Uses the LDAP transport to perform NTLM authentication and retrieve settings
    /// </summary>
    /// <param name="endpoint"></param>
    /// <param name="options"></param>
    /// <returns></returns>
    protected internal virtual async Task<bool> Authenticate(Uri endpoint, LdapAuthOptions options, NtlmAuthenticationHandler ntlmAuth = null, LdapTransport ldapTransport = null, CancellationToken cancellationToken = default) {
        var host = endpoint.Host;
        var auth = ntlmAuth ?? new NtlmAuthenticationHandler($"LDAP/{host.ToUpper()}") {
            Options = options
        };
        var transport = ldapTransport ?? new LdapTransport(_log, endpoint);

        try {
            transport.InitializeConnectionAsync(_ldapTimeout);
            await auth.PerformNtlmAuthenticationAsync(transport, cancellationToken);
            return true;
        } catch (LdapNativeException ex) {
            switch (ex.ErrorCode) {
                case (int)LdapErrorCodes.InvalidCredentials:
                    // If NTLM is blocked via GPO, the server returns the following error message:
                    //   "80090302: LdapErr: DSID-0C090816, comment: AcceptSecurityContext error, data 1, v6673"
                    //   0x80090302 == SEC_E_UNSUPPORTED_FUNCTION
                    if (ex.ServerErrorMessage.StartsWith(SEC_E_UNSUPPORTED_FUNCTION)) {
                        _log.LogDebug("LDAP endpoint '{endpoint}' does not support NTLM", endpoint);
                        return false;
                    }

                    if (ex.ServerErrorMessage.StartsWith(SEC_E_BAD_BINDINGS)) {
                        _log.LogDebug("Bad bindings with the LDAPS endpoint '{endpoint}'. Server error: {serverError}",
                            endpoint, ex.ServerErrorMessage);
                        return false;
                    } else {
                        _log.LogError(
                            "Unhandled LDAP InvalidCred error code during LDAP test: {ex}, Server error: {err}", ex,
                            ex.ServerErrorMessage);
                        break;
                    }
                case (int)LdapErrorCodes.StrongAuthRequired:
                    _log.LogDebug("LDAP requires signing. Endpoint: {endpoint}", endpoint);
                    return false;
                case (int)LdapErrorCodes.ServerDown:
                    _log.LogDebug("LDAP endpoint '{endpoint}' not accessible", endpoint);
                    return false;
                default:
                    _log.LogError("Unhandled LdapException error code during LDAP test: {ex}, Server error: {err}", ex,
                        ex.ServerErrorMessage);
                    break;
            }
        } catch (InvalidOperationException ex) {
            _log.LogDebug("LDAP InvalidOperationException: {message}", ex.Message);
        } catch (Exception ex)
        {
            _log.LogError("An unhandled error occurred during the LDAP test: {ex}", ex);
        }

        return false;
    }
    
    private async Task SendComputerStatus(CSVComputerStatus status) {
        if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
    }
}