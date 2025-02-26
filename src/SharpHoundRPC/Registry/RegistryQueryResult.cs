#nullable enable
namespace SharpHoundRPC.Registry {
    using Microsoft.Win32;


    public class RegistryQueryResult {
        public RegistryQueryResult(string keyPath, string valueName, object? value, RegistryValueKind? valueKind,
            bool valueExists) {
            KeyPath = keyPath;
            ValueName = valueName;
            Value = value;
            ValueKind = valueKind;
            ValueExists = valueExists;
        }

        public string KeyPath { get; set; }
        public string ValueName { get; set; }
        public object? Value { get; set; }
        public RegistryValueKind? ValueKind { get; set; }
        public bool ValueExists { get; set; }
    }
#nullable disable
}