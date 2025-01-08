#nullable enable
using Microsoft.Win32;
using System.Collections.Generic;

namespace SharpHoundRPC.Registry;

public class RegistryQuery(RegistryHive hive, string keyPath)
{
    public RegistryHive Hive { get; set; } = hive;
    public string KeyPath { get; set; } = keyPath;

    // If not set, returns all values in the key
    public IEnumerable<string>? ValueNames { get; set; }


    // Helper methods for fluent configuration
    public static RegistryQuery ForKey(RegistryHive hive, string keyPath)
    {
        return new RegistryQuery(hive, keyPath);
    }

    public RegistryQuery WithValues(params string[] valueNames)
    {
        ValueNames = valueNames;
        return this;
    }
}
#nullable disable
