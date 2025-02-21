
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

public class LdapTransport(ILogger logger, Uri ldapEndpoint) : INtlmTransport, IDisposable {
    private LdapConnection? _ldap;
    private bool _disposed;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate bool VerifyServerCert(
        IntPtr Connection,
        IntPtr pServerCert
    );

    public bool IsSecureLdap {
        get { return ldapEndpoint.Scheme == "ldaps"; }
    }

    private void ThrowIfDisposed() {
        if (_disposed) {
            throw new ObjectDisposedException(nameof(LdapConnection));
        }
    }

    private void ThrowIfHandleNull() {
        if (_ldap == null) {
            throw new NullReferenceException("LDAP handle is null");
        }
    }

    public void InitializeConnectionAsync(int timeout = -1) {
        if (_ldap == null) {
            _ldap = new LdapConnection();
            try {
                _ldap.Initialize(ldapEndpoint.Host, ldapEndpoint.Port);
                _ldap.SetOption(LdapOption.ProtocolVersion, LdapOptionValue.Version3);

                if (IsSecureLdap) {
                    _ldap.SetOption(
                        LdapOption.ServerCertificate,
                        Marshal.GetFunctionPointerForDelegate<VerifyServerCert>((connection, serverCert) => true)
                    );
                }

                _ldap.Connect(timeout);
                logger.LogDebug($"LDAP connection established to {ldapEndpoint.Host}:{ldapEndpoint.Port}");
            } catch (Exception) {
                _ldap.Dispose();
                _ldap = null;
                throw;
            }
        }
    }

    public Task<byte[]> NegotiateAsync(byte[] negotiateMessage) {
        ThrowIfDisposed();
        ThrowIfHandleNull();

        return Task.Run(() => _ldap!.SaslBind("", LdapSupportedSaslMechanisms.GSS_SPNEGO, negotiateMessage));
    }

    public async Task<Object> AuthenticateAsync(byte[] authenticateMessage) {
        ThrowIfDisposed();
        ThrowIfHandleNull();

        return await Task.Run(() => {
            InitializeConnectionAsync();
            var bytes = _ldap!.SaslBind("", LdapSupportedSaslMechanisms.GSS_SPNEGO, authenticateMessage);
            return bytes;
        });
    }

    public void Dispose() {
        if (!_disposed) {
            if (_ldap != null) {
                _ldap.Dispose();
                _ldap = null;
            }

            _disposed = true;
        }
    }
}