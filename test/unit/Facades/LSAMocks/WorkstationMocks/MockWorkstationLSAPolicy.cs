using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Principal;
using SharpHoundCommonLib.Enums;
using SharpHoundRPC;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace CommonLibTest.Facades.LSAMocks.WorkstationMocks
{
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class MockWorkstationLSAPolicy : ILSAPolicy
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
            IEnumerable<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)> principals = userRight switch
            {
                LSAPrivileges.RemoteInteractiveLogon => new List<(SecurityIdentifier, string, SharedEnums.SidNameUse, string)>
                {
                    (new SecurityIdentifier("S-1-5-32-555"), "Remote Desktop Users", SharedEnums.SidNameUse.Alias, "abc"),
                    (new SecurityIdentifier("S-1-5-32-544"), "Administrators", SharedEnums.SidNameUse.Alias, "abc"),
                    (new SecurityIdentifier("S-1-5-32-551"), "Backup Operators", SharedEnums.SidNameUse.Alias, "abc"),
                },
                LSAPrivileges.Backup => new List<(SecurityIdentifier, string, SharedEnums.SidNameUse, string)>
                {
                    (new SecurityIdentifier("S-1-5-32-551"), "Backup Operators", SharedEnums.SidNameUse.Alias, "abc"),
                    (new SecurityIdentifier("S-1-5-32-544"), "Administrators", SharedEnums.SidNameUse.Alias, "abc"),
                },
                LSAPrivileges.Restore => new List<(SecurityIdentifier, string, SharedEnums.SidNameUse, string)>
                {
                    (new SecurityIdentifier("S-1-5-32-551"), "Backup Operators", SharedEnums.SidNameUse.Alias, "abc"),
                    (new SecurityIdentifier("S-1-5-32-544"), "Administrators", SharedEnums.SidNameUse.Alias, "abc"),
                },
                _ => new List<(SecurityIdentifier, string, SharedEnums.SidNameUse, string)>
                {
                    (new SecurityIdentifier("S-1-5-32-544"), "Administrators", SharedEnums.SidNameUse.Alias, "abc"),
                }
            };

            return Result<IEnumerable<(SecurityIdentifier sid, string Name, SharedEnums.SidNameUse Use, string Domain)>>.Ok(principals);
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
