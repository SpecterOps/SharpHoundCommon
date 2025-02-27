using System.Collections.Generic;
using SharpHoundRPC;
using SharpHoundRPC.Wrappers;
using System.Security.Principal;

namespace CommonLibTest.Facades
{
    public class MockFailSAMAliasUsers_GetMembers : ISAMAlias
    {
        public Result<IEnumerable<SecurityIdentifier>> GetMembers()
        {
            return NtStatus.StatusAccessDenied;
        }
    }
}

