using System.Collections.Concurrent;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace SharpHoundCommonLib
{
    public class DomainInfo
    {
        public string DomainSID { get; set; }
        public string DomainFQDN { get; set; }
        public string DomainSearchBase { get; set; }
        public string DomainConfigurationPath { get; set; }
        public string DomainNetbiosName { get; set; }

        public override string ToString()
        {
            return $"{nameof(DomainSID)}: {DomainSID}, {nameof(DomainFQDN)}: {DomainFQDN}, {nameof(DomainSearchBase)}: {DomainSearchBase}, {nameof(DomainConfigurationPath)}: {DomainConfigurationPath}, {nameof(DomainNetbiosName)}: {DomainNetbiosName}";
        }
    }
}