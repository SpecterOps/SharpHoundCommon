#nullable enable

using Microsoft.Win32.SafeHandles;
using SharpHoundCommonLib.Enums;
using System;
using System.Runtime.InteropServices;

namespace SharpHoundCommonLib.Ntlm;

public class SafeLdapHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeLdapHandle(IntPtr handle) : base(true)
    {
        this.handle = handle;
    }

    protected override bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            int result = NativeMethods.ldap_unbind_s(handle);
            return result == 0;
        }
        return true;
    }
}

public class LdapConnection : IDisposable
{
    private SafeLdapHandle? _handle;
    private bool _disposed;

    public SafeLdapHandle Handle
    {
        get
        {
            ThrowIfDisposed();
            return _handle ?? throw new InvalidOperationException("LDAP connection not initialized");
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(LdapConnection));
        }
    }

    private string? GetServerError()
    {
        ThrowIfDisposed();

        try
        {
            IntPtr errorMessagePtr;
            int result = NativeMethods.ldap_get_option(
                Handle,
                LdapOption.ServerError,
                out errorMessagePtr
            );

            if (result != 0 || errorMessagePtr == IntPtr.Zero)
                return null;

            try
            {
                return Marshal.PtrToStringAnsi(errorMessagePtr);
            }
            finally
            {
                NativeMethods.ldap_memfree(errorMessagePtr);
            }
        }
        catch
        {
            // If anything goes wrong getting the server error,
            // return null rather than throw since we're already
            // in error handling code
            return null;
        }
    }

    public void CheckError(int result, string operation)
    {
        if (result != 0)
        {
            int lastError = NativeMethods.LdapGetLastError();
            string? serverError = GetServerError();
            throw new LdapException(
                $"LDAP operation failed. Operation: {operation}. API error code: {result}",
                lastError,
                serverError
            );
        }
    }

    public void Initialize(string hostName, int port)
    {
        ThrowIfDisposed();

        var handle = NativeMethods.ldap_init(hostName, port);
        if (handle == IntPtr.Zero)
        {
            int lastError = NativeMethods.LdapGetLastError();
            throw new LdapException($"Failed to initialize LDAP connection", lastError);
        }

        _handle = new SafeLdapHandle(handle);
    }

    public void Connect(int timeout = -1)
    {
        ThrowIfDisposed();

        var timeoutPtr = IntPtr.Zero;
        try
        {
            if (timeout >= 0)
            {
                var ldapTimeout = new LDAP_TIMEVAL
                {
                    tv_sec = (int)(new TimeSpan(0, 0, timeout).Ticks / TimeSpan.TicksPerSecond),
                };
                timeoutPtr = Marshal.AllocHGlobal(Marshal.SizeOf(ldapTimeout));
                Marshal.StructureToPtr(ldapTimeout, timeoutPtr, false);
            }

            int result = NativeMethods.ldap_connect(Handle, timeoutPtr);
            CheckError(result, "Connecting to LDAP server");
        }
        finally
        {
            if (timeoutPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(timeoutPtr);
            }
        }
    }

    private T GetOption<T>(LdapOption option) where T : struct
    {
        ThrowIfDisposed();

        if (typeof(T) == typeof(int))
        {
            int value;
            int result = NativeMethods.ldap_get_option(Handle, option, out value);
            CheckError(result, $"Getting LDAP option {option}");
            return (T)(object)value;
        }

        throw new ArgumentException($"Unsupported option type: {typeof(T).Name}");
    }

    public void SetOption(LdapOption option, LdapOptionValue value)
    {
        ThrowIfDisposed();

        // Get current value
        int currentValue = GetOption<int>(option);
        int newValue = (int)value;

        // Only set if different
        if (currentValue != newValue)
        {
#pragma warning disable CS8604 // Possible null reference argument.
            int result = NativeMethods.ldap_set_option(_handle, option, ref newValue);
#pragma warning restore CS8604 // Possible null reference argument.
            CheckError(result, $"Setting LDAP option {option}");

            // Verify the change
            int verifyValue = GetOption<int>(option);
            if (verifyValue != newValue)
            {
                throw new LdapException($"Failed to verify option change for {option}. Expected {newValue} but got {verifyValue}",
                    NativeMethods.LdapGetLastError());
            }
        }
    }

    public void SetOption(LdapOption option, IntPtr value)
    {
#pragma warning disable CS8604 // Possible null reference argument.
        int result = NativeMethods.ldap_set_option(_handle, option, value);
#pragma warning restore CS8604 // Possible null reference argument.
        CheckError(result, $"Setting LDAP option {option}");
    }

    private int GetResultCode()
    {
        ThrowIfDisposed();

        int resultCode;
        int result = NativeMethods.ldap_get_option(
            Handle,
            LdapOption.ResultCode,
            out resultCode
        );

        CheckError(result, "Getting LDAP result code");
        return resultCode;
    }

    public byte[] SaslBind(string distinguishedName, string mechanism, byte[] credential)
    {
        ThrowIfDisposed();

        IntPtr credPtr = IntPtr.Zero;
        try
        {
            // Create berval structure for credentials
            var berval = new BERVAL
            {
                bv_len = credential.Length,
                bv_val = Marshal.AllocHGlobal(credential.Length)
            };

            Marshal.Copy(credential, 0, berval.bv_val, credential.Length);

            credPtr = Marshal.AllocHGlobal(Marshal.SizeOf<BERVAL>());
            Marshal.StructureToPtr(berval, credPtr, false);

            // Perform SASL bind
            int result = NativeMethods.ldap_sasl_bind_s(
                Handle,
                distinguishedName,
                mechanism,
                credPtr,
                IntPtr.Zero,  // No server controls
                IntPtr.Zero,  // No client controls
                out IntPtr response
            );

            if (result != (int)LdapErrorCodes.Success &&
                result != (int)LdapErrorCodes.SaslBindInProgress)
            {
                throw new LdapException("SASL bind failed", result, GetServerError());
            }

            int bindResultCode = GetResultCode();

            if (bindResultCode != (int)LdapErrorCodes.Success &&
                bindResultCode != (int)LdapErrorCodes.SaslBindInProgress)
            {
                throw new LdapException("SASL bind result failed", bindResultCode, GetServerError());
            }

            if (response == IntPtr.Zero)
                throw new InvalidOperationException("Server did return a challenge");

            var responseBerval = Marshal.PtrToStructure<BERVAL>(response);
            byte[] responseData = new byte[responseBerval.bv_len];
            Marshal.Copy(responseBerval.bv_val, responseData, 0, responseBerval.bv_len);
            return responseData;
        }
        finally
        {
            if (credPtr != IntPtr.Zero)
            {
                var berval = Marshal.PtrToStructure<BERVAL>(credPtr);
                if (berval.bv_val != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(berval.bv_val);
                }
                Marshal.FreeHGlobal(credPtr);
            }

            // Freeing the memory always results in crashes. Is it managed by something else?
            //if (response != IntPtr.Zero)
            //{
            //    var responseBerval = Marshal.PtrToStructure<NativeMethods.berval>(response);
            //    if (responseBerval.bv_val != IntPtr.Zero)
            //    {
            //        Marshal.FreeHGlobal(responseBerval.bv_val);
            //    }
            //    Marshal.FreeHGlobal(response);
            //}
        }
    }
    public void Dispose()
    {
        if (!_disposed)
        {
            _handle?.Dispose();
            _handle = null;
            _disposed = true;
        }
    }
}


[StructLayout(LayoutKind.Sequential)]
public struct LDAP_TIMEVAL
{
    public int tv_sec;
    public int tv_usec;
}

[StructLayout(LayoutKind.Sequential)]
public struct BERVAL
{
    public int bv_len;
    public IntPtr bv_val;
}
public class NativeMethods
{

    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr ldap_init(string Host, int Port);

    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ldap_connect(SafeLdapHandle ld, IntPtr timeout);

    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ldap_set_option(SafeLdapHandle ld, LdapOption option, ref int value);

    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ldap_set_option(SafeLdapHandle ld, LdapOption option, IntPtr value);

    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ldap_get_option(SafeLdapHandle ld, LdapOption option, out int value);
    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ldap_get_option(SafeLdapHandle ld, LdapOption option, out IntPtr value);

    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void ldap_memfree(IntPtr ptr);

    [DllImport("Wldap32.dll", EntryPoint = "ldap_sasl_bind_s", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ldap_sasl_bind_s(
        SafeLdapHandle ld,
        string dn,
        string mechanism,
        IntPtr cred,
        IntPtr serverctrls,
        IntPtr clientctrls,
        out IntPtr msgidp);

    [DllImport("Wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ldap_unbind_s(IntPtr ld);

    [DllImport("wldap32.dll", EntryPoint = "LdapGetLastError")]
    public static extern int LdapGetLastError();
}

#nullable disable