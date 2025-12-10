using System;
using System.IO;
using System.Security;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib {
    public interface IRegistryAccessor {
        public RegistryResult GetRegistryKeyData(string target, string subkey, string subvalue, ILogger log);
        public IRegistryKey OpenRemoteRegistry(string target);
        public Task<IRegistryKey> Connect(RegistryHive hive, string machineName);
    }

    public class RegistryAccessor : IRegistryAccessor {
        private static readonly AdaptiveTimeout _adaptiveTimeout =
            new AdaptiveTimeout(maxTimeout: TimeSpan.FromSeconds(10), Logging.LogProvider.CreateLogger(nameof(SHRegistryKey)));
        
        public RegistryResult GetRegistryKeyData(string target, string subkey, string subvalue, ILogger log) {
            var data = new RegistryResult();

            try {
                var baseKey = OpenRemoteRegistry(target);
                var value = baseKey.GetValue(subkey, subvalue);
                data.Value = value;
                data.Collected = true;
            } 
            catch (IOException e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                    target, subkey, subvalue);
                data.FailureReason = "Target machine was not found or not connectable";
            } 
            catch (SecurityException e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                  target, subkey, subvalue);
                data.FailureReason = "User does not have the proper permissions to perform this operation";
            }
            catch (UnauthorizedAccessException e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                  target, subkey, subvalue);
                data.FailureReason = "User does not have the necessary registry rights";
            }
            catch (Exception e) {
                log.LogDebug(e, "Error getting data from registry for {Target}: {RegSubKey}:{RegValue}",
                  target, subkey, subvalue);
                data.FailureReason = e.Message;
            }

            return data;
        }

        public IRegistryKey OpenRemoteRegistry(string target) {
            return Connect(RegistryHive.LocalMachine, target).GetAwaiter().GetResult();
        }

        /// <summary>
        ///     Gets a handle to a remote registry.
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
        public async Task<IRegistryKey> Connect(RegistryHive hive, string machineName) {
            var remoteKey = await _adaptiveTimeout.ExecuteWithTimeout((_) => RegistryKey.OpenRemoteBaseKey(hive, machineName));
            if (remoteKey.IsSuccess)
                return new SHRegistryKey(remoteKey.Value);
            throw new TimeoutException($"Failed to connect to registry on {machineName}: {remoteKey.Error}");
        }
    }
}