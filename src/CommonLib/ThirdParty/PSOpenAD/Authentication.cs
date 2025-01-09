#nullable enable
using System;
using System.Buffers;
using System.Runtime.InteropServices;

namespace SharpHoundCommonLib.ThirdParty.PSOpenAD;

public enum AuthenticationMethod {
    /// <summary>Selects the best auth mechanism available.</summary>
    Default,

    /// <summary>No authentication.</summary>
    Anonymous,

    /// <summary>
    /// Simple auth with a plaintext username and password, should only be used with LDAPS or StartTLS.
    /// </summary>
    Simple,

    /// <summary>GSSAPI/SSPI Negotiate (SASL GSS-SPNEGO) authentication.</summary>
    Negotiate,

    /// <summary>GSSAPI/SSPI Kerberos (SASL GSSAPI) authentication</summary>
    Kerberos,

    /// <summary>Authentication using a client provided X.509 Certificate for LDAP or StartTLS.</summary>
    Certificate,

    // <summary>Authentication using NTLM</summary>
    NTLM
}

/// <summary>Details on an authentication mechanism for the local client.</summary>
public sealed class AuthenticationProvider {
    /// <summary>The authentication mechanism this represents.</summary>
    public AuthenticationMethod Method { get; }

    /// <summary>The SASL mechanism identifier for this provider.</summary>
    public string SaslId { get; }

    /// <summary>Whether the client can use this provider.</summary>
    public bool Available { get; }

    /// <summary>Whether this authentication mechanism can sign/encrypt data over a non-TLS connection.</summary>
    public bool CanSign { get; }

    /// <summary>Further details on why the mechanism is not available.</summary>
    public string Details { get; }

    public AuthenticationProvider(AuthenticationMethod method, string saslId, bool available, bool canSign,
        string details) {
        Method = method;
        SaslId = saslId;
        Available = available;
        CanSign = canSign;
        Details = details;
    }
}

internal enum GssapiProvider {
    None,
    MIT,
    Heimdal,
    GSSFramework,
    SSPI,
}

[Flags]
internal enum SASLSecurityFlags : byte {
    None = 0,
    NoSecurity = 1,
    Integrity = 2,
    Confidentiality = 4,
}

public class ChannelBindings {
    public int InitiatorAddrType { get; set; }
    public byte[]? InitiatorAddr { get; set; }
    public int AcceptorAddrType { get; set; }
    public byte[]? AcceptorAddr { get; set; }
    public byte[]? ApplicationData { get; set; }
}

internal abstract class SecurityContext : IDisposable {
    public bool Complete { get; internal set; }
    public bool IntegrityAvailable { get; internal set; }
    public bool ConfidentialityAvailable { get; internal set; }

    public abstract byte[] Step(byte[]? inputToken = null);
    public abstract byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt);
    public abstract byte[] Unwrap(ReadOnlySpan<byte> data);

    public abstract uint MaxWrapSize(uint outputSize, bool confReq);

    public abstract void Dispose();
    ~SecurityContext() => Dispose();
}

internal class ExternalContext : SecurityContext {
    private bool _called;

    public override byte[] Step(byte[]? inputToken = null) {
        // No actual tokens are exchanged but we need to return at least 1 empty array and set it to be completed
        // on the next call
        Complete = _called;
        _called = true; // Next call with set Complete = true

        return Array.Empty<byte>();
    }

    public override byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt) => Array.Empty<byte>();
    public override byte[] Unwrap(ReadOnlySpan<byte> data) => Array.Empty<byte>();
    public override uint MaxWrapSize(uint outputSize, bool confReq) => 0;

    public override void Dispose() {
    }
}

internal class SspiContext : SecurityContext {
    private readonly SafeSspiCredentialHandle _credential;
    private readonly byte[]? _bindingData;
    private readonly string _targetSpn;
    private readonly InitiatorContextRequestFlags _flags = InitiatorContextRequestFlags.ISC_REQ_MUTUAL_AUTH;
    private SafeSspiContextHandle? _context;
    private uint _blockSize = 0;
    private uint _trailerSize = 0;
    private uint _seqNo = 0;

    public SspiContext(string? username, string? password, AuthenticationMethod method, string target,
        ChannelBindings? channelBindings, bool integrity, bool confidentiality) {
        _bindingData = CreateChannelBindings(channelBindings);
        _targetSpn = target;

        var package = Enum.GetName(typeof(AuthenticationMethod), method);
        WinNTAuthIdentity? identity = null;
        if (!string.IsNullOrEmpty(username) || !string.IsNullOrEmpty(password)) {
            string? domain = null;
            if (username?.Contains("\\") == true) {
                var stringSplit = username.Split(['\\'], 2);
                domain = stringSplit[0];
                username = stringSplit[1];
            }

            identity = new WinNTAuthIdentity(username, domain, password);
        }

        _credential = SSPI.AcquireCredentialsHandle(null, package, CredentialUse.SECPKG_CRED_OUTBOUND,
            identity).Creds;

        const InitiatorContextRequestFlags integrityFlags = InitiatorContextRequestFlags.ISC_REQ_INTEGRITY |
                                                            InitiatorContextRequestFlags.ISC_REQ_SEQUENCE_DETECT;

        if (integrity)
            _flags |= integrityFlags;

        if (confidentiality)
            _flags |= integrityFlags | InitiatorContextRequestFlags.ISC_REQ_CONFIDENTIALITY;

        if (method == AuthenticationMethod.Kerberos) {
            // Kerberos uses a special SASL wrapping mechanism and always requires integrity
            _flags |= integrityFlags;
        } else if (!integrity && !confidentiality) {
            // GSS-SPNEGO uses the context flags to determine the protection applied and Kerberos always sets
            // INTEG by default. By setting this flag we unset INTEG allowing it to be used without any protection.
            _flags |= InitiatorContextRequestFlags.ISC_REQ_NO_INTEGRITY;
        }
    }

    public override byte[] Step(byte[]? inputToken = null) {
        var bufferCount = 0;
        if (inputToken != null)
            bufferCount++;

        if (_bindingData != null)
            bufferCount++;

        unsafe {
            fixed (byte* input = inputToken, cbBuffer = _bindingData) {
                Span<Helpers.SecBuffer> inputBuffers = stackalloc Helpers.SecBuffer[bufferCount];
                var idx = 0;

                if (inputToken != null) {
                    inputBuffers[idx].cbBuffer = (uint)inputToken.Length;
                    inputBuffers[idx].BufferType = (uint)SecBufferType.SECBUFFER_TOKEN;
                    inputBuffers[idx].pvBuffer = (IntPtr)input;
                    idx++;
                }

                if (_bindingData != null) {
                    inputBuffers[idx].cbBuffer = (uint)_bindingData.Length;
                    inputBuffers[idx].BufferType = (uint)SecBufferType.SECBUFFER_CHANNEL_BINDINGS;
                    inputBuffers[idx].pvBuffer = (IntPtr)cbBuffer;
                }

                var context = SSPI.InitializeSecurityContext(_credential, _context, _targetSpn, _flags,
                    TargetDataRep.SECURITY_NATIVE_DREP, inputBuffers, [SecBufferType.SECBUFFER_TOKEN]);
                _context = context.Context;

                if (!context.MoreNeeded) {
                    Complete = true;
                    IntegrityAvailable =
                        (context.Flags & InitiatorContextReturnFlags.ISC_RET_INTEGRITY) != 0;
                    ConfidentialityAvailable =
                        (context.Flags & InitiatorContextReturnFlags.ISC_RET_CONFIDENTIALITY) != 0;

                    Span<Helpers.SecPkgContext_Sizes> sizes = stackalloc Helpers.SecPkgContext_Sizes[1];
                    fixed (Helpers.SecPkgContext_Sizes* sizesPtr = sizes) {
                        SSPI.QueryContextAttributes(_context, SecPkgAttribute.SECPKG_ATTR_SIZES,
                            (IntPtr)sizesPtr);

                        _trailerSize = sizes[0].cbSecurityTrailer;
                        _blockSize = sizes[0].cbBlockSize;
                    }
                }

                return context.OutputBuffers.Length > 0 ? context.OutputBuffers[0] : Array.Empty<byte>();
            }
        }
    }

    public override byte[] Wrap(ReadOnlySpan<byte> data, bool encrypt) {
        if (_context == null || !Complete)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        unsafe {
            var shared = ArrayPool<byte>.Shared;
            var token = shared.Rent((int)_trailerSize);
            var padding = shared.Rent((int)_blockSize);

            try {
                fixed (byte* tokenPtr = token, dataPtr = data, paddingPtr = padding) {
                    Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[3];
                    buffers[0].BufferType = (uint)SecBufferType.SECBUFFER_TOKEN;
                    buffers[0].cbBuffer = _trailerSize;
                    buffers[0].pvBuffer = (IntPtr)tokenPtr;

                    buffers[1].BufferType = (uint)SecBufferType.SECBUFFER_DATA;
                    buffers[1].cbBuffer = (uint)data.Length;
                    buffers[1].pvBuffer = (IntPtr)dataPtr;

                    buffers[2].BufferType = (uint)SecBufferType.SECBUFFER_PADDING;
                    buffers[2].cbBuffer = _blockSize;
                    buffers[2].pvBuffer = (IntPtr)paddingPtr;

                    var qop = encrypt ? 0 : 0x80000001; // SECQOP_WRAP_NO_ENCRYPT
                    SSPI.EncryptMessage(_context, qop, buffers, NextSeqNo());

                    var wrapped = new byte[buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer];
                    var offset = 0;
                    if (buffers[0].cbBuffer > 0) {
                        Buffer.BlockCopy(token, 0, wrapped, offset, (int)buffers[0].cbBuffer);
                        offset += (int)buffers[0].cbBuffer;
                    }

                    Marshal.Copy((IntPtr)dataPtr, wrapped, offset, (int)buffers[1].cbBuffer);
                    offset += (int)buffers[1].cbBuffer;

                    if (buffers[2].cbBuffer > 0) {
                        Buffer.BlockCopy(padding, 0, wrapped, offset, (int)buffers[2].cbBuffer);
                        offset += (int)buffers[2].cbBuffer;
                    }

                    return wrapped;
                }
            } finally {
                shared.Return(token);
                shared.Return(padding);
            }
        }
    }

    public override byte[] Unwrap(ReadOnlySpan<byte> data) {
        if (_context == null || !Complete)
            throw new InvalidOperationException("Cannot wrap without a completed context");

        unsafe {
            fixed (byte* dataPtr = data) {
                Span<Helpers.SecBuffer> buffers = stackalloc Helpers.SecBuffer[2];
                buffers[0].BufferType = (uint)SecBufferType.SECBUFFER_STREAM;
                buffers[0].cbBuffer = (uint)data.Length;
                buffers[0].pvBuffer = (IntPtr)dataPtr;

                buffers[1].BufferType = (uint)SecBufferType.SECBUFFER_DATA;
                buffers[1].cbBuffer = 0;
                buffers[1].pvBuffer = IntPtr.Zero;

                SSPI.DecryptMessage(_context, buffers, NextSeqNo());

                var unwrapped = new byte[buffers[1].cbBuffer];
                Marshal.Copy(buffers[1].pvBuffer, unwrapped, 0, unwrapped.Length);

                return unwrapped;
            }
        }
    }

    public override uint MaxWrapSize(uint outputSize, bool confReq) {
        throw new NotImplementedException(); // Not used in SSPI.
    }

    private byte[]? CreateChannelBindings(ChannelBindings? bindings) {
        if (bindings == null)
            return null;

        var structOffset = Marshal.SizeOf<Helpers.SEC_CHANNEL_BINDINGS>();
        var binaryLength = bindings.InitiatorAddr?.Length ?? 0 + bindings.AcceptorAddr?.Length ?? 0 +
            bindings.ApplicationData?.Length ?? 0;
        var bindingData = new byte[structOffset + binaryLength];
        unsafe {
            fixed (byte* bindingPtr = bindingData) {
                var bindingStruct = (Helpers.SEC_CHANNEL_BINDINGS*)bindingPtr;

                bindingStruct->dwInitiatorAddrType = (uint)bindings.InitiatorAddrType;
                if (bindings.InitiatorAddr != null) {
                    bindingStruct->cbInitiatorLength = (uint)bindings.InitiatorAddr.Length;
                    bindingStruct->dwInitiatorOffset = (uint)structOffset;
                    Buffer.BlockCopy(bindings.InitiatorAddr, 0, bindingData, structOffset,
                        bindings.InitiatorAddr.Length);

                    structOffset += bindings.InitiatorAddr.Length;
                }

                bindingStruct->dwAcceptorAddrType = (uint)bindings.AcceptorAddrType;
                if (bindings.AcceptorAddr != null) {
                    bindingStruct->cbAcceptorLength = (uint)bindings.AcceptorAddr.Length;
                    bindingStruct->dwAcceptorOffset = (uint)structOffset;
                    Buffer.BlockCopy(bindings.AcceptorAddr, 0, bindingData, structOffset,
                        bindings.AcceptorAddr.Length);

                    structOffset += bindings.AcceptorAddr.Length;
                }

                if (bindings.ApplicationData != null) {
                    bindingStruct->cbApplicationDataLength = (uint)bindings.ApplicationData.Length;
                    bindingStruct->dwApplicationDataOffset = (uint)structOffset;
                    Buffer.BlockCopy(bindings.ApplicationData, 0, bindingData, structOffset,
                        bindings.ApplicationData.Length);
                }
            }
        }

        return bindingData;
    }

    private uint NextSeqNo() {
        var seqNo = _seqNo;
        _seqNo++;

        return seqNo;
    }

    public override void Dispose() {
        _credential.Dispose();
        _context?.Dispose();
    }
}
#nullable disable