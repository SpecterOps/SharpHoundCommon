using SharpHoundCommonLib.OutputTypes;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib.Processors
{
    public class DCRegistryProcessor
    {
        private readonly ILogger _log;
        private readonly IRegistryAccessor _registryAccessor;
        
        public readonly ILdapUtils _utils;
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);

        public DCRegistryProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _registryAccessor = new RegistryAccessor(log);
            _log = log ?? Logging.LogProvider.CreateLogger("DCRegProc");
        }

        internal DCRegistryProcessor(ILdapUtils utils, IRegistryAccessor registryAccessor, ILogger log = null)
        {
            _utils = utils;
            _registryAccessor = registryAccessor;
            _log = log ?? Logging.LogProvider.CreateLogger("DCRegProc");
        }

        /// <summary>
        /// Gets the Windows build number reported by a domain controller.
        /// </summary>
        /// <param name="target">Domain controller to query.</param>
        /// <returns>The CurrentBuildNumber registry value and collection status.</returns>
        public StrRegistryAPIResult GetCurrentBuildNumber(string target)
        {
            var ret = new StrRegistryAPIResult();
            const string subKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            const string subValue = "CurrentBuildNumber";
            var data = _registryAccessor.GetRegistryKeyData(target, subKey, subValue);

            if (!data.Collected)
            {
                ret.FailureReason = data.FailureReason;
                return ret;
            }

            if (data.Value == null)
            {
                ret.FailureReason = "Registry value was not found";
                return ret;
            }

            ret.Collected = true;
            ret.Value = (string)data.Value;
            return ret;
        }

        /// <summary>
        /// Gets the Windows update build revision reported by a domain controller.
        /// </summary>
        /// <param name="target">Domain controller to query.</param>
        /// <returns>The UBR registry value and collection status.</returns>
        public IntRegistryAPIResult GetCurrentBuildRevision(string target)
        {
            var ret = new IntRegistryAPIResult();
            const string subKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            const string subValue = "UBR";
            var data = _registryAccessor.GetRegistryKeyData(target, subKey, subValue);

            if (!data.Collected)
            {
                ret.FailureReason = data.FailureReason;
                return ret;
            }

            if (data.Value == null)
            {
                ret.FailureReason = "Registry value was not found";
                return ret;
            }

            ret.Collected = true;
            ret.Value = (int)data.Value;
            return ret;
        }

        /// <summary>
        /// This function gets the CertificateMappingMethods registry value stored on DCs.
        /// </summary>
        /// <remarks>https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16</remarks>
        /// <param name="target"></param>
        /// <returns>IntRegistryAPIResult</returns>
        [ExcludeFromCodeCoverage]
        public IntRegistryAPIResult GetCertificateMappingMethods(string target)
        {
            var ret = new IntRegistryAPIResult();
            const string subKey = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel";
            const string subValue = "CertificateMappingMethods";
            var data = _registryAccessor.GetRegistryKeyData(target, subKey, subValue);

            ret.Collected = data.Collected;
            if (!data.Collected)
            {
                ret.FailureReason = data.FailureReason;
                return ret;
            }

            if (data.Value == null)
            {
                ret.Value = -1;    
                return ret;
            }

            ret.Value = (int)data.Value;

            return ret;
        }

        /// <summary>
        /// This function gets the StrongCertificateBindingEnforcement registry value stored on DCs.
        /// </summary>
        /// <remarks>https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16</remarks>
        /// <param name="target"></param>
        /// <returns>IntRegistryAPIResult</returns>
        [ExcludeFromCodeCoverage]
        public IntRegistryAPIResult GetStrongCertificateBindingEnforcement(string target)
        {
            var ret = new IntRegistryAPIResult();
            const string subKey = @"SYSTEM\CurrentControlSet\Services\Kdc";
            const string subValue = "StrongCertificateBindingEnforcement";
            var data = _registryAccessor.GetRegistryKeyData(target, subKey, subValue);

            ret.Collected = data.Collected;
            if (!data.Collected)
            {
                ret.FailureReason = data.FailureReason;
                return ret;
            }

            if (data.Value == null)
            {
                ret.Value = -1;    
                return ret;
            }

            ret.Value = (int)data.Value;

            return ret;
        }

        /// <summary>
        /// This function gets the VulnerableChannelAllowList registry value stored on DCs.
        /// </summary>
        /// <remarks>https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e</remarks>
        /// <param name="target"></param>
        /// <returns>StrRegistryAPIResult</returns>
        [ExcludeFromCodeCoverage]
        public StrRegistryAPIResult GetVulnerableNetlogonSecurityDescriptor(string target)
        {
            var ret = new StrRegistryAPIResult();
            const string subKey = @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters";
            const string subValue = "VulnerableChannelAllowList";
            var data = _registryAccessor.GetRegistryKeyData(target, subKey, subValue);

            ret.Collected = data.Collected;
            if (!data.Collected)
            {
                ret.FailureReason = data.FailureReason;
                return ret;
            }

            if (data.Value == null)
            {
                return ret;
            }

            ret.Value = (string)data.Value;

            return ret;
        }
    }
}
