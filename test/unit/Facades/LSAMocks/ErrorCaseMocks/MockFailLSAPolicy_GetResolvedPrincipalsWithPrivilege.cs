using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Principal;
using SharpHoundRPC;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades.LSAMocks.WorkstationMocks
{
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class MockFailLSAPolicy_GetResolvedPrincipalsWithPrivilege : ILSAPolicy
    {
        public Result<(string Name, string Sid)> GetLocalDomainInformation()
        {
            return ("WIN10", Consts.MockWorkstationMachineSid);
        }

        public Result<IEnumerable<SecurityIdentifier>> GetPrincipalsWithPrivilege(string userRight)
        {
            throw new NotImplementedException();
        }

        public Result<IEnumerable<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            GetResolvedPrincipalsWithPrivilege(string userRight)
        {
            return NtStatus.StatusAccessDenied;
        }

        public Result<(string Name, SharedEnums.SidNameUse Use, string Domains)> LookupSid(SecurityIdentifier sid)
        {
            throw new NotImplementedException();
        }

        public Result<IEnumerable<(SecurityIdentifier Sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>
            LookupSids(SecurityIdentifier[] sids)
        {
            throw new NotImplementedException();
        }
    }
}