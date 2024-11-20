using System;
using System.Collections.Generic;
using SharpHoundRPC;
using SharpHoundRPC.SAMRPCNative;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades
{
    public class MockFailDomainBuiltIn_PreviouslyCached : ISAMDomain
    {
        public Result<(string Name, SharedEnums.SidNameUse Type)> LookupPrincipalByRid(int rid)
        {
            throw new System.NotImplementedException();
        }

        public Result<IEnumerable<(string Name, int Rid)>> GetAliases()
        {
            var result = new List<(string, int)>
            {
                ("administrators", 544),
                ("remote desktop users", 555)
            };
            return result;
        }

        public Result<ISAMAlias> OpenAlias(int rid, SAMEnums.AliasOpenFlags desiredAccess = SAMEnums.AliasOpenFlags.ListMembers)
        {
            if (rid == 544)
            {
                return new MockFailAliasAdministrators_PreviouslyCached();
            }
            if (rid == 555)
            {
                return new MockFailAlias_PreviouslyCached();
            }

            throw new NotImplementedException();
        }

        public Result<ISAMAlias> OpenAlias(string name)
        {
            throw new System.NotImplementedException();
        }
    }
}