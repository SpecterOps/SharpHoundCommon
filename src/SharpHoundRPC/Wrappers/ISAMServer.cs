using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.Wrappers
{
    public interface ISAMServer
    {
        Result<IEnumerable<(string Name, int Rid)>> GetDomains();
        Result<SecurityIdentifier> LookupDomain(string name);
        Result<SecurityIdentifier> GetMachineSid(string testName = null, CancellationToken cancellationToken = default);

        Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalBySid(
            SecurityIdentifier securityIdentifier);

        Result<ISAMDomain> OpenDomain(string domainName, SAMEnums.DomainAccessMask requestedDomainAccess =
            SAMEnums.DomainAccessMask.Lookup |
            SAMEnums.DomainAccessMask.ListAccounts,
            CancellationToken cancellationToken = default);

        Result<ISAMDomain> OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess =
                SAMEnums.DomainAccessMask.Lookup |
                SAMEnums.DomainAccessMask.ListAccounts);
    }
}