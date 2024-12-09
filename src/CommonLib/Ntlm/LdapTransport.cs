#nullable enable

using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

public class LdapTransport(ILogger logger, Uri ldapEndpoint) : INtlmTransport, IDisposable
{
    private LdapConnection? _ldap;
    private bool _disposed;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool VerifyServerCert(
       IntPtr Connection,
       IntPtr pServerCert
    );

    public bool IsLdaps
    {
        get { return ldapEndpoint.Scheme == "ldaps"; }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(LdapConnection));
        }
    }

    private void ThrowIfHandleNull()
    {
        if (_ldap == null)
        {
            throw new NullReferenceException("LDAP handle is null");
        }
    }

    public void InitializeConnectionAsync(int timeout = -1)
    {
        if (_ldap == null)
        {
            _ldap = new LdapConnection();
            try
            {
                _ldap.Initialize(ldapEndpoint.Host, ldapEndpoint.Port);
                _ldap.SetOption(LdapOption.ProtocolVersion, LdapOptionValue.Version3);

                if (IsLdaps)
                {
                    _ldap.SetOption(
                        LdapOption.ServerCertificate,
                        Marshal.GetFunctionPointerForDelegate<VerifyServerCert>((connection, serverCert) => true)
                    );

                    // Not necessary to call. Internally, it automagically sets it via the LDAPS port specified
                    //_ldap.SetOption(LdapOption.Ssl, LdapOptionValue.On);

                    // Not setting Signing/Encryption since the API returns LDAP_UNWILLING_TO_PERFORM when SSL is enabled
                    //_ldap.SetOption(LdapOption.Sign, LdapOptionValue.On);
                    //_ldap.SetOption(LdapOption.Encrypt, LdapOptionValue.On);
                }

                _ldap.Connect(timeout);
                logger.LogDebug($"LDAP connection established to {ldapEndpoint.Host}:{ldapEndpoint.Port}");
            }
            catch (Exception)
            {
                _ldap.Dispose();
                _ldap = null;
                throw;
            }
        }
    }

    public Task<byte[]> NegotiateAsync(byte[] negotiateMessage)
    {
        ThrowIfDisposed();
        ThrowIfHandleNull();

        return Task.Run(() =>
        {
            return _ldap!.SaslBind("", LdapSupportedSaslMechansims.GSS_SPNEGO, negotiateMessage);
        });

    }

    public async Task<Object> AuthenticateAsync(byte[] authenticateMessage)
    {
        ThrowIfDisposed();
        ThrowIfHandleNull();

        return await Task.Run(() =>
        {
            InitializeConnectionAsync();
            var bytes = _ldap!.SaslBind("", LdapSupportedSaslMechansims.GSS_SPNEGO, authenticateMessage);
            return bytes;
        });
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_ldap != null)
            {
                _ldap.Dispose();
                _ldap = null;
            }
            _disposed = true;
        }
    }
}

#nullable disable