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
    public class MockFailSAMServer_OpenDomain : ISAMServer
    {
        public bool IsNull { get; }
        public Result<IEnumerable<(string Name, int Rid)>> GetDomains()
        {
            var domains = new List<(string, int)>
            {
                ("BUILTIN", 1)
            };
            return domains;
        }

        public virtual Result<SecurityIdentifier> LookupDomain(string name)
        {
            throw new System.NotImplementedException();
        }

        public Result<SecurityIdentifier> GetMachineSid(string testName = null)
        {
            var securityIdentifier = new SecurityIdentifier(Consts.MockWorkstationMachineSid);
            return Result<SecurityIdentifier>.Ok(securityIdentifier);
        }

        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalBySid(SecurityIdentifier securityIdentifier)
        {
            throw new System.NotImplementedException();
        }

        public Result<ISAMDomain> OpenDomain(string domainName,
            SAMEnums.DomainAccessMask requestedDomainAccess = SAMEnums.DomainAccessMask.ListAccounts | SAMEnums.DomainAccessMask.Lookup)
        {
            // if (domainName.Equals("builtin", StringComparison.OrdinalIgnoreCase))
            // {
            //     return new MockDCDomainBuiltIn();
            // }

            return NtStatus.StatusAccessDenied;
        }

        public Result<ISAMDomain> OpenDomain(SecurityIdentifier securityIdentifier,
            SAMEnums.DomainAccessMask requestedDomainAccess = SAMEnums.DomainAccessMask.ListAccounts | SAMEnums.DomainAccessMask.Lookup)
        {
            throw new System.NotImplementedException();
        }
    }
}