#nullable enable
namespace SharpHoundRPC.Registry;

using Microsoft.Win32;
using SharpHoundRPC.PortScanner;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;


public class RemoteRegistryStrategy : ICollectionStrategy<RegistryQueryResult, RegistryQuery>
{
    private readonly IPortScanner _portScanner;
    private const int SmbPort = 445;

    public RemoteRegistryStrategy(IPortScanner scanner)
    {
        _portScanner = scanner;
    }

    public async Task<(bool, string)> CanExecute(string targetMachine)
    {
        if (string.IsNullOrEmpty(targetMachine))
        {
            throw new ArgumentException("Target machine cannot be null or empty", nameof(targetMachine));
        }

        try
        {
            var isOpen = await _portScanner.CheckPort(targetMachine, SmbPort, true);
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
        if (string.IsNullOrEmpty(targetMachine))
            throw new ArgumentException("Target machine cannot be null or empty", nameof(targetMachine));

        if (queries == null || !queries.Any())
            throw new ArgumentException("Queries cannot be null or empty", nameof(queries));



        return await Task.Run(() =>
        {
            var results = new List<RegistryQueryResult>();

            try
            {
                foreach (var query in queries)
                {
                    ValidateQuery(query);

                    using var baseKey = OpenRemoteBaseKey(targetMachine, query.Hive);
                    results.AddRange(EnumerateKey(baseKey, query.KeyPath, query));
                }
            }
            catch (Exception ex)
            {
                var errorMessage = $"Failed to enumerate registry on {targetMachine}: {ex}";
                throw new RemoteRegistryException(errorMessage, ex);
            }

            return results;
        }).ConfigureAwait(false);
    }

    private RegistryKey OpenRemoteBaseKey(string targetMachine, RegistryHive hive)
    {
        try
        {
            bool isLocalMachine = NativeUtils.IsCurrentMachineFqdn(targetMachine);

            return isLocalMachine
                ? RegistryKey.OpenBaseKey(hive, RegistryView.Registry64)
                : RegistryKey.OpenRemoteBaseKey(hive, targetMachine, RegistryView.Registry64);
        }
        catch (Exception ex)
        {
            throw new RemoteRegistryException(
                $"Failed to open remote registry base key on {targetMachine} for hive {hive}", ex);
        }
    }

    private void ValidateQuery(RegistryQuery query)
    {
        if (query == null)
            throw new ArgumentNullException(nameof(query));

        if (string.IsNullOrEmpty(query.KeyPath))
            throw new ArgumentException("Registry key path cannot be null or empty", nameof(query));
    }

    private IEnumerable<RegistryQueryResult> EnumerateKey(
    RegistryKey baseKey,
    string keyPath,
    RegistryQuery query)
    {
        var results = new List<RegistryQueryResult>();

        try
        {
            using var key = string.IsNullOrEmpty(keyPath)
                ? baseKey
                : baseKey.OpenSubKey(keyPath);

            if (key == null)
                throw new RemoteRegistryException($"Key not found: {keyPath}");

            // If no specific values requested, get all values
            if (query.ValueNames == null)
            {
                foreach (var valueName in key.GetValueNames())
                {
                    results.Add(new RegistryQueryResult(
                        key.Name,
                        valueName,
                        key.GetValue(valueName),
                        key.GetValueKind(valueName),
                        true));
                }
            }
            // If specific values requested, check each one
            else
            {
                foreach (var requestedValue in query.ValueNames)
                {
                    var valueNames = key.GetValueNames();
                    var exists = valueNames.Contains(requestedValue, StringComparer.OrdinalIgnoreCase);

                    results.Add(new RegistryQueryResult(
                        key.Name,
                        requestedValue,
                        exists ? key.GetValue(requestedValue) : null,
                        exists ? key.GetValueKind(requestedValue) : null,
                        exists));
                }
            }
        }
        catch (Exception ex)
        {
            throw new RemoteRegistryException($"Failed to enumerate registry key {keyPath}", ex);
        }

        return results;
    }
}

/// <summary>
/// Exception thrown when remote registry operations fail
/// </summary>
public class RemoteRegistryException : Exception
{
    public RemoteRegistryException(string message) : base(message) { }
    public RemoteRegistryException(string message, Exception innerException)
        : base(message, innerException) { }
}
#nullable disable