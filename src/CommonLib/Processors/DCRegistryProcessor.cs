using SharpHoundCommonLib.OutputTypes;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace SharpHoundCommonLib.Processors
{
    public class DCRegistryProcessor
    {
        private readonly ILogger _log;
        public readonly ILdapUtils _utils;
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);

        public DCRegistryProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("DCRegProc");
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
            var data = Helpers.GetRegistryKeyData(target, subKey, subValue, _log);

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
            var data = Helpers.GetRegistryKeyData(target, subKey, subValue, _log);

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
            var data = Helpers.GetRegistryKeyData(target, subKey, subValue, _log);

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