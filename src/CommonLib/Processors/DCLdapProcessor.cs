#nullable enable
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Ntlm;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.ThirdParty.PSOpenAD;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors;

public class LdapAuthOptions
{
    public bool Signing { get; set; }
    public ChannelBindings? Bindings { get; set; }
}

public class DCLdapProcessor
{
    private readonly ILogger _log;
    private readonly PortScanner _scanner;
    private readonly int _portScanTimeout;
    private readonly int _ldapTimeout;
    private readonly Uri _ldapEndpoint;
    private readonly Uri _ldapSslEndpoint;

    private readonly string SEC_E_UNSUPPORTED_FUNCTION = "80090302";
    private readonly string SEC_E_BAD_BINDINGS = "80090346";


    public DCLdapProcessor(int portScanTimeout, string dcHostname, ILogger log)
    {
        _log = log;
        _scanner = new PortScanner();
        _portScanTimeout = portScanTimeout;
        _ldapTimeout = portScanTimeout / 1000;
        _ldapEndpoint = new Uri($"ldap://{dcHostname}:389");
        _ldapSslEndpoint = new Uri($"ldaps://{dcHostname}:636");
    }

    public async Task<LdapService> Scan()
    {
        var hasLdap = await TestLdapPort();
        var hasLdaps = await TestLdapsPort();
        ApiResult<bool> isSigningRequired = new(),
            isChannelBindingDisabled = new();

        if (hasLdap)
        {
            isSigningRequired = await CheckIsNtlmSigningRequired();
        }

        if (hasLdaps)
        {
            isChannelBindingDisabled = await CheckIsChannelBindingDisabled();
        }

        return new LdapService(
            hasLdap,
            hasLdaps,
            isSigningRequired,
            isChannelBindingDisabled
        );
    }

    /// <summary>
    /// Tests if the specified Ldap port is open
    /// </summary>
    /// <param name="target">Hostname of the machine</param>
    /// <param name="target">TCP port being tested</param>
    /// <returns>bool</returns>
    [ExcludeFromCodeCoverage]
    public async Task<bool> TestLdapPort()
    {
        return await _scanner.CheckPort(_ldapEndpoint.Host, _ldapEndpoint.Port, _portScanTimeout);
    }

    [ExcludeFromCodeCoverage]
    public async Task<bool> TestLdapsPort()
    {
        return await _scanner.CheckPort(_ldapSslEndpoint.Host, _ldapSslEndpoint.Port, _portScanTimeout);
    }

    public async Task<ApiResult<bool>> CheckIsNtlmSigningRequired()
    {
        try
        {
            var options = new LdapAuthOptions()
            {
                Signing = false
            };
            var accessibleWithoutSigning = await Authenticate(_ldapEndpoint, options);

            return ApiResult<bool>.CreateSuccess(accessibleWithoutSigning == false);
        }
        catch (Exception ex)
        {
            return ApiResult<bool>.CreateError($"CheckIsNtlmSigningRequired failed: {ex}");
        }
    }

    // Checks if EPA is enabled. Does so by trying to auth with wrong channel bingings.
    // If auth is successful despite the wrong bindings, then EPA is not required.
    // Note: Ideally we'd check if it works under 3 conditions:
    // 1) No channel bindings to check if configured to "Never"
    // 2) Invalid bindings to check if configured to "Always" (would error)
    // 3) Correct bindings to ensure NTLM auth is enabled
    // However, as of right now we only do #2. We can't do #1 right now since the
    // Window's SSPI APIs (InitSecurityContext) always add channel bindings.
    public async Task<ApiResult<bool>> CheckIsChannelBindingDisabled()
    {
        try
        {
            // 1) Can we connect with *invalid* bindings

            var bindings = new ChannelBindings
            {
                ApplicationData = [0, 0, 0, 0]
            };
            var accessibleWithNoBindings = await Authenticate(_ldapSslEndpoint, new LdapAuthOptions()
            {
                Signing = false,
                Bindings = bindings
            });

            return ApiResult<bool>.CreateSuccess(accessibleWithNoBindings == true);

            //// Second, check if we can connect, but with *INVALID* bindings
            //// This is to check if it's configured for "When Supported"
            //var bindings = new ChannelBindings();
            //bindings.ApplicationData = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            //var accessibleWithBadBindings = await Authenticate(_ldapSslEndpoint, new LdapAuthOptions()
            //{
            //    Signing = true,
            //    Bindings = bindings
            //});

            //if (accessibleWithBadBindings)
            //    return ApiResult<bool>.CreateSuccess(false);

            // Third, check if we can connect with *CORRECT* bindings to see if NTLM is enabled
            //var cert = await SslUtils.GetServerCertificate(_ldapSslEndpoint.Host);
            //var bindings = SslUtils.GetTlsChannelBindings(cert);
            //var accessible = await Authenticate(_ldapSslEndpoint, new LdapAuthOptions()
            //{
            //    Signing = true,
            //    Bindings = bindings
            //});

            //if (accessible)
            //    return ApiResult<bool>.CreateSuccess(true);

            //throw new InvalidOperationException("Could not access any LDAP endpoints");
        }
        catch (Exception ex)
        {
            return ApiResult<bool>.CreateError($"CheckIsNtlmSigningRequired failed: {ex}");
        }
    }

    private async Task<bool> Authenticate(Uri endpoint, LdapAuthOptions options)
    {
        var host = endpoint.Host;
        var auth = new NtlmAuthenticationHandler(_log, host, $"LDAP/{host.ToUpper()}")
        {
            Options = options
        };
        var transport = new LdapTransport(_log, endpoint);

        try
        {
            transport.InitializeConnectionAsync(_ldapTimeout);
            var bytes = (byte[])await auth.PerformNtlmAuthenticationAsync(transport);
            return true;
        }
        catch (LdapException ex)
        {
            switch (ex.ErrorCode)
            {
                case (int)LdapErrorCodes.InvalidCredentials:
                    // If NTLM is blocked via GPO, the server returns the following error message:
                    //   "80090302: LdapErr: DSID-0C090816, comment: AcceptSecurityContext error, data 1, v6673"
                    //   0x80090302 == SEC_E_UNSUPPORTED_FUNCTION
                    if (ex.ServerErrorMessage.StartsWith(SEC_E_UNSUPPORTED_FUNCTION))
                    {
                        _log.LogDebug("LDAP endpoint '{endpoint}' does not support NTLM", endpoint);
                        return false;
                    }
                    if (ex.ServerErrorMessage.StartsWith(SEC_E_BAD_BINDINGS))
                    {
                        _log.LogDebug("Bad bindings with the LDAPS endpoint '{endpoint}'. Server error: {serverError}", endpoint, ex.ServerErrorMessage);
                        return false;
                    }
                    else
                    {
                        _log.LogError("Unhandled LDAP InvalidCred error code during LDAP test: {ex}, Server error: {err}", ex, ex.ServerErrorMessage);
                        break;
                    }
                case (int)LdapErrorCodes.StrongAuthRequired:
                    _log.LogDebug("LDAP requires signing. Endpoint: {endpoint}", endpoint);
                    return false;
                case (int)LdapErrorCodes.ServerDown:
                    _log.LogDebug("LDAP endpoint '{endpoint}' not accessible", endpoint);
                    return false;
                default:
                    _log.LogError("Unhandled LdapException error code during LDAP test: {ex}, Server error: {err}", ex, ex.ServerErrorMessage);
                    break;
            }
        }
        catch (Exception ex)
        {
            _log.LogError("An unhandled error occurred during the LDAP test: {ex}", ex);
        }

        return false;
    }

    //private Task<bool> CanAccessWithChannelBindings()
    //{
    //    return Task.Run(() =>
    //    {
    //        var timeout = TimeSpan.FromSeconds(5);

    //        try
    //        {
    //            using var conn = new System.DirectoryServices.Protocols.LdapConnection(
    //                new LdapDirectoryIdentifier(_ldapEndpoint.Host, _ldapEndpoint.Port, false, false),
    //                null,
    //                AuthType.Ntlm
    //                )
    //            {
    //                AuthType = AuthType.Ntlm,
    //                AutoBind = false,
    //                Timeout = timeout,
    //                SessionOptions =
    //                {
    //                    SspiFlag = (int)InitiatorContextRequestFlags.ISC_REQ_CONNECTION,
    //                    RootDseCache = false,
    //                    Signing = false,
    //                    Sealing = false,
    //                    SendTimeout = timeout,
    //                    VerifyServerCertificate =
    //                        (connection, certificate) =>
    //                        {
    //                            return true;
    //                        }
    //                }
    //            };

    //            conn.Bind();

    //            return true;
    //        }
    //        catch (System.DirectoryServices.Protocols.LdapException ex)
    //        {
    //            switch (ex.ErrorCode)
    //            {
    //                case (int)LdapErrorCodes.InvalidCredentials:
    //                    // If NTLM is blocked via GPO, the server returns the following error message:
    //                    //   "80090302: LdapErr: DSID-0C090816, comment: AcceptSecurityContext error, data 1, v6673"
    //                    //   0x80090302 == SEC_E_UNSUPPORTED_FUNCTION
    //                    if (ex.ServerErrorMessage.StartsWith(SEC_E_UNSUPPORTED_FUNCTION))
    //                    {
    //                        _log.LogDebug("LDAP endpoint '{endpoint}' does not support NTLM", _ldapEndpoint);
    //                        return false;
    //                    }
    //                    else
    //                    {
    //                        _log.LogError("Unhandled LDAP InvalidCred error code during LDAP test: {ex}, Server error: {err}", ex, ex.ServerErrorMessage);
    //                        break;
    //                    }
    //                case (int)LdapErrorCodes.ServerDown:
    //                    _log.LogDebug("LDAP endpoint '{endpoint}' not accessible", _ldapEndpoint);
    //                    return false;
    //                default:
    //                    _log.LogError("Unhandled LdapException error code during LDAP test: {ex}, Server error: {err}", ex, ex.ServerErrorMessage);
    //                    break;
    //            }
    //        }
    //        catch (Exception ex)
    //        {
    //            _log.LogError("An unhandled error occurred during the LDAP test: {ex}", ex);
    //        }

    //        return false;
    //    });
    //}
}

#nullable disable