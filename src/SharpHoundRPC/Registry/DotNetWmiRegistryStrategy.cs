#nullable enable
using Microsoft.Win32;
using SharpHoundRPC.PortScanner;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Management;
using System.Threading.Tasks;

namespace SharpHoundRPC.Registry;

/// <summary>
/// Collects registry values remotely using WMI's StdRegProv class.
/// </summary>
public class DotNetWmiRegistryStrategy : ICollectionStrategy<RegistryQueryResult, RegistryQuery>
{
    private readonly IPortScanner _portScanner;
    private const int EpMapperPort = 135;

    /// <summary>
    /// AD domain name used for authentication.
    /// </summary>
    public string Domain { get; set; }

    /// <summary>
    /// Whether to use Kerberos instead of NTLM. Defaults to true.
    /// Defaults to true.
    /// </summary>
    public bool UseKerberos { get; set; } = true;


    /// <summary>
    /// Creates a new WMI registry strategy
    /// </summary>
    /// <param name="scanner">Port scanner for connectivity checks</param>
    /// <param name="domain">AD domain name</param>
    public DotNetWmiRegistryStrategy(IPortScanner scanner, string domain)
    {
        _portScanner = scanner;
        Domain = domain;
    }

    public async Task<(bool, string)> CanExecute(string targetMachine)
    {
        try
        {
            var isOpen = await _portScanner.CheckPort(targetMachine, EpMapperPort, true);
            return (isOpen, string.Empty);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    public async Task<IEnumerable<RegistryQueryResult>> ExecuteAsync(
        string targetMachine,
        IEnumerable<RegistryQuery> queries)
    {
        return await Task.Run(() =>
        {
            var results = new List<RegistryQueryResult>();
            bool isLocalMachine = NativeUtils.IsCurrentMachineFqdn(targetMachine);
            ManagementScope scope;

            if (isLocalMachine)
            {
                scope = new ManagementScope("root\\cimv2");
            }
            else
            {
                var connectionOptions = new ConnectionOptions
                {
                    Authority = UseKerberos
                        ? @$"kerberos:{Domain}\{targetMachine}"
                        : @$"ntlmdomain:{Domain}"
                };

                scope = new ManagementScope(
                    $"\\\\{targetMachine}\\root\\cimv2",
                    connectionOptions);
            }

            scope.Connect();

            using var reg = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);

            foreach (var query in queries)
            {
                if (query.ValueNames == null) continue;

                var methodParams = reg.GetMethodParameters("EnumValues");
                methodParams["hDefKey"] = (UInt32)query.Hive;
                methodParams["sSubKeyName"] = query.KeyPath;

                using var outParams = reg.InvokeMethod("EnumValues", methodParams, null);

                var valueNames = (string[])outParams["sNames"];
                var types = (int[])outParams["Types"];

                // For each requested value, check if it exists and add result accordingly
                foreach (var requestedValue in query.ValueNames)
                {
                    var valueIndex = Array.FindIndex(
                        valueNames,
                        name => string.Equals(name, requestedValue, StringComparison.OrdinalIgnoreCase));

                    if (valueIndex != -1)
                    {
                        var value = GetValue(
                            reg,
                            query.Hive,
                            query.KeyPath,
                            requestedValue,
                            types[valueIndex]);

                        results.Add(new RegistryQueryResult(
                            query.KeyPath,
                            requestedValue,
                            value,
                            (RegistryValueKind)types[valueIndex],
                            true));
                    }
                    else
                    {
                        results.Add(new RegistryQueryResult(
                            query.KeyPath,
                            requestedValue,
                            null,
                            null,
                            false));
                    }
                }
            }

            return results;
        }).ConfigureAwait(false);
    }

    /// <summary>
    /// Gets a registry value of the specified type
    /// </summary>
    private object GetValue(
        ManagementClass reg,
        RegistryHive hive,
        string keyPath,
        string valueName,
        int valueType)
    {
        var methodParams = reg.GetMethodParameters("GetStringValue");
        methodParams["hDefKey"] = (UInt32)hive;
        methodParams["sSubKeyName"] = keyPath;
        methodParams["sValueName"] = valueName;

        (string methodName, string propertyName) = (RegistryValueKind)valueType switch
        {
            RegistryValueKind.String => ("GetStringValue", "sValue"),
            RegistryValueKind.ExpandString => ("GetExpandedStringValue", "sValue"),
            RegistryValueKind.Binary => ("GetBinaryValue", "uValue"),
            RegistryValueKind.DWord => ("GetDWORDValue", "uValue"),
            RegistryValueKind.MultiString => ("GetMultiStringValue", "sValue"),
            RegistryValueKind.QWord => ("GetQWORDValue", "uValue"),
            _ => throw new InvalidEnumArgumentException($"Unsupported WMI registry value type. Type: {valueType}  Name: {valueName}")
        };

        using var outParams = reg.InvokeMethod(methodName, methodParams, null);
        return outParams[propertyName];
    }
}

#nullable disable