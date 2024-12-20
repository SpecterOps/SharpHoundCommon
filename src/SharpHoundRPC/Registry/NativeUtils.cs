using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static SharpHoundRPC.NetAPINative.NetAPIEnums;

namespace SharpHoundRPC.Registry;

public static class NativeUtils
{
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool GetComputerNameEx([In] ComputerNameFormat nameType, [MarshalAs(UnmanagedType.LPTStr)][In][Out] StringBuilder lpBuffer, [In][Out] ref int size);
    public enum ComputerNameFormat
    {
        NetBIOS,
        DnsHostname,
        DnsDomain,
        DnsFullyQualified,
        PhysicalNetBIOS,
        PhysicalDnsHostname,
        PhysicalDnsDomain,
        PhysicalDnsFullyQualified
    }

    // Dictionary to cache computer names by format type
    private static readonly Dictionary<ComputerNameFormat, string> _cachedNames = new();

    public static string GetComputerName(ComputerNameFormat nameType)
    {
        // Check if we have a cached result
        if (_cachedNames.TryGetValue(nameType, out string cachedName))
        {
            return cachedName;
        }

        int num = 0;
        if (!GetComputerNameEx(nameType, null, ref num))
        {
            int lastWin32Error = Marshal.GetLastWin32Error();
            // If it isn't the "more data" error, something else is wrong
            if (lastWin32Error != (int)NetAPIStatus.ErrorMoreData)
            {
                throw new Win32Exception(lastWin32Error);
            }
        }

        if (num < 0)
        {
            throw new Exception("Invalid length: " + num.ToString());
        }

        StringBuilder stringBuilder = new StringBuilder(num);
        if (!GetComputerNameEx(nameType, stringBuilder, ref num))
        {
            int lastWin32Error2 = Marshal.GetLastWin32Error();
            throw new Win32Exception(lastWin32Error2);
        }

        string result = stringBuilder.ToString();
        _cachedNames[nameType] = result; // Cache the result
        return result;
    }

    /// <summary>
    /// Checks if the provided FQDN matches the current host's FQDN.
    /// </summary>
    /// <param name="fqdnToCheck">The FQDN to compare against the current host's FQDN.</param>
    /// <returns>True if they match; otherwise false.</returns>
    public static bool IsCurrentMachineFqdn(string fqdnToCheck)
    {
        if (string.IsNullOrEmpty(fqdnToCheck))
            return false;

        // Retrieve the current host's fully qualified domain name (FQDN)
        string hostFqdn = GetComputerName(ComputerNameFormat.DnsFullyQualified);

        // Case-insensitive comparison to accommodate any casing differences
        return string.Equals(hostFqdn, fqdnToCheck, StringComparison.OrdinalIgnoreCase);
    }
}
