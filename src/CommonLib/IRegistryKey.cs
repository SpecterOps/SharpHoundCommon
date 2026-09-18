using System;
using Microsoft.Win32;

namespace SharpHoundCommonLib {
    public interface IRegistryKey: IDisposable {
        public object GetValue(string subkey, string name);
        public string[] GetSubKeyNames();
    }

    public class SHRegistryKey : IRegistryKey {
        private readonly RegistryKey _currentKey;
        
        public SHRegistryKey(RegistryKey registryKey) {
            _currentKey = registryKey;
        }

        public object GetValue(string subkey, string name) {
            var key = _currentKey.OpenSubKey(subkey);
            return key?.GetValue(name);
        }

        public string[] GetSubKeyNames() => _currentKey.GetSubKeyNames();

        public void Dispose() {
            _currentKey.Dispose();
        }
    }
}