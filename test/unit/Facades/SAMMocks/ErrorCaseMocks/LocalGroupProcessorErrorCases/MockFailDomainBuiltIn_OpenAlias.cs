using System;
using System.Collections.Generic;
using SharpHoundRPC;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    public class MockFailDomainBuiltIn_OpenAlias : ISAMDomain
    {
        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalByRid(int rid)
        {
            throw new System.NotImplementedException();
        }

        public Result<IEnumerable<(string Name, int Rid)>> GetAliases()
        {
            var results = new List<(string, int)>
            {
                ("Administrators", 544)
            };
            return results;
        }

        public Result<ISAMAlias> OpenAlias(int rid, SAMEnums.AliasOpenFlags desiredAccess = SAMEnums.AliasOpenFlags.ListMembers)
        {
            // switch (rid)
            // {
            //     case 544:
            //         return new MockDCAliasAdministrators();
            //     case 545:
            //         return new MockDCAliasUsers();
            //     default:
            //         throw new IndexOutOfRangeException();
            // }
            return NtStatus.StatusAccessDenied;
        }

        public Result<ISAMAlias> OpenAlias(string name)
        {
            throw new System.NotImplementedException();
        }
    }
}