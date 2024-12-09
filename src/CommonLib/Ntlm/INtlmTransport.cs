using System;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Ntlm;

public interface INtlmTransport
{
    Task<byte[]> NegotiateAsync(byte[] negotiateMessage);
    Task<Object> AuthenticateAsync(byte[] authenticateMessage);
}