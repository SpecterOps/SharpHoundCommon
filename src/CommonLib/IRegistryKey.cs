using System;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace SharpHoundCommonLib {
    public interface IRegistryKey {
        public object GetValue(string subkey, string name);
        public string[] GetSubKeyNames();
    }

    public class SHRegistryKey : IRegistryKey, IDisposable {
        private readonly RegistryKey _currentKey;

        private SHRegistryKey(RegistryKey registryKey) {
            _currentKey = registryKey;
        }

        public object GetValue(string subkey, string name) {
            var key = _currentKey.OpenSubKey(subkey);
            return key?.GetValue(name);
        }

        public string[] GetSubKeyNames() => _currentKey.GetSubKeyNames();

        /// <summary>
        /// Gets a handle to a remote registry.
        /// </summary>
        /// <param name="hive"></param>
        /// <param name="machineName"></param>
        /// <returns></returns>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="System.IO.IOException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="System.Security.SecurityException"></exception>
        /// <exception cref="UnauthorizedAccessException"></exception>
        public static async Task<SHRegistryKey> Connect(RegistryHive hive, string machineName) {
            var remoteKey = await Timeout.ExecuteWithTimeout(TimeSpan.FromSeconds(10), (_) => RegistryKey.OpenRemoteBaseKey(hive, machineName));
            if (remoteKey.IsSuccess)
                return new SHRegistryKey(remoteKey.Value);
            else
                throw new TimeoutException("Timeout");
        }

        public void Dispose() {
            _currentKey.Dispose();
        }
    }

    public class MockRegistryKey : IRegistryKey {
        public virtual object GetValue(string subkey, string name) {
            //Unimplemented
            return default;
        }

        public virtual string[] GetSubKeyNames() {
            throw new NotImplementedException();
        }
    }
}