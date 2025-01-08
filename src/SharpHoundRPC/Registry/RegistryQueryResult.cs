#nullable enable
namespace SharpHoundRPC.Registry;

using Microsoft.Win32;


public class RegistryQueryResult(string keyPath, string valueName, object? value, RegistryValueKind? valueKind, bool valueExists)
{
    public string KeyPath { get; set; } = keyPath;
    public string ValueName { get; set; } = valueName;
    public object? Value { get; set; } = value;
    public RegistryValueKind? ValueKind { get; set; } = valueKind;
    public bool ValueExists { get; set; } = valueExists;
}
#nullable disable
