using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class MockFailSAMServer_PreviouslyCached : ISAMServer
    {
        public bool IsNull { get; }
        public Result<IEnumerable<(string Name, int Rid)>> GetDomains()
        {
            var domains = new List<(string, int)>
            {
                ("WIN10", 0),
                ("BUILTIN", 1)
            };
            return domains;
        }

        public Result<SecurityIdentifier> LookupDomain(string name)
        {
            throw new NotImplementedException();
        }

        public Result<SecurityIdentifier> GetMachineSid(string testName = null)
        {
            var securityIdentifier = new SecurityIdentifier(Consts.MockWorkstationMachineSid);
            return Result<SecurityIdentifier>.Ok(securityIdentifier);
        }

        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalBySid(SecurityIdentifier securityIdentifier)
        {
            switch (securityIdentifier.Value)
            {
                case "S-1-5-21-321011808-3761883066-353627080-500":
                    return ("Administrator", SharedEnums.SidNameUse.User);
                case "S-1-5-21-321011808-3761883066-353627080-1000":
                    return ("DefaultUser", SharedEnums.SidNameUse.User);
                case "S-1-5-21-321011808-3761883066-353627080-1003":
                    return ("TestGroup", SharedEnums.SidNameUse.Alias);
                default:
                    throw new IndexOutOfRangeException();
            }
        }

        public Result<ISAMDomain> OpenDomain(string domainName,
            SAMEnums.DomainAccessMask requestedDomainAccess = SAMEnums.DomainAccessMask.ListAccounts | SAMEnums.DomainAccessMask.Lookup)
        {
            if (domainName.Equals("win10", StringComparison.OrdinalIgnoreCase))
            {
                return new MockWorkstationDomainWIN10();
            }
            return new MockFailDomainBuiltIn_PreviouslyCached();
        }

        public Result<ISAMDomain> OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess = SAMEnums.DomainAccessMask.ListAccounts | SAMEnums.DomainAccessMask.Lookup)
        {
            return new MockFailDomainBuiltIn_PreviouslyCached();
        }
    }
}