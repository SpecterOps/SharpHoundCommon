using Microsoft.Win32;

namespace SharpHoundCommonLib
{
    public interface IRegistryKey
    {
        public object GetValue(string subkey, string name);
    }

    public class SHRegistryKey : IRegistryKey
    {
        private RegistryKey _currentKey;

        public SHRegistryKey(RegistryHive hive, string machineName)
        {
            var remoteKey = RegistryKey.OpenRemoteBaseKey(hive, machineName);
            _currentKey = remoteKey;
        }

        public object GetValue(string subkey, string name)
        {
            var key = _currentKey.OpenSubKey(subkey);
            return key?.GetValue(name);
        }
    }

    public class MockRegistryKey : IRegistryKey
    {
        public virtual object GetValue(string subkey, string name) {
            //Unimplemented
            return default;
        }
    }
}