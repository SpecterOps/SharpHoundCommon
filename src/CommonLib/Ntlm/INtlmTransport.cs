using System;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

public interface INtlmTransport {
    Task<byte[]> NegotiateAsync(byte[] negotiateMessage);
    Task<object> AuthenticateAsync(byte[] authenticateMessage);
}