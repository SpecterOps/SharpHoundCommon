using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC;
using SharpHoundRPC.Shared;
using SharpHoundRPC.Wrappers;

namespace SharpHoundCommonLib.Processors
{
    public class UserRightsAssignmentProcessor
    {
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);

        private readonly ILogger _log;
        private readonly ILdapUtils _utils;

        public UserRightsAssignmentProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("UserRightsAssignmentProcessor");
        }

        public event ComputerStatusDelegate ComputerStatusEvent;

        public virtual SharpHoundRPC.Result<ILSAPolicy> OpenLSAPolicy(string computerName)
        {
            var result = LSAPolicy.OpenPolicy(computerName);
            if (result.IsFailed) return SharpHoundRPC.Result<ILSAPolicy>.Fail(result.SError);

            return SharpHoundRPC.Result<ILSAPolicy>.Ok(result.Value);
        }

        public IAsyncEnumerable<UserRightsAssignmentAPIResult> GetUserRightsAssignments(ResolvedSearchResult result,
            string[] desiredPrivileges = null)
        {
            return GetUserRightsAssignments(result.DisplayName, result.ObjectId, result.Domain,
                result.IsDomainController, desiredPrivileges);
        }

        /// <summary>
        ///     Gets principals with the requested privileges on the target computer
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerObjectId">The objectid of the computer in the domain</param>
        /// <param name="computerDomain"></param>
        /// <param name="isDomainController">Is the computer a domain controller</param>
        /// <param name="desiredPrivileges"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<UserRightsAssignmentAPIResult> GetUserRightsAssignments(string computerName,
            string computerObjectId, string computerDomain, bool isDomainController, string[] desiredPrivileges = null, TimeSpan timeout = default)
        {
            if (timeout == default) {
                timeout = TimeSpan.FromMinutes(2);
            }
            var policyOpenResult = await Task.Run(() => OpenLSAPolicy(computerName)).TimeoutAfter(timeout);
            if (!policyOpenResult.IsSuccess)
            {
                _log.LogDebug("LSAOpenPolicy failed on {ComputerName} with status {Status}", computerName,
                    policyOpenResult.Error);
                await SendComputerStatus(new CSVComputerStatus
                {
                    Task = "LSAOpenPolicy",
                    ComputerName = computerName,
                    Status = policyOpenResult.Error
                });
                yield break;
            }

            var server = policyOpenResult.Value;
            desiredPrivileges ??= LSAPrivileges.DesiredPrivileges;

            SecurityIdentifier machineSid;
            if (!Cache.GetMachineSid(computerObjectId, out var temp))
            {
                var getMachineSidResult = await Task.Run(() => server.GetLocalDomainInformation()).TimeoutAfter(timeout);
                if (getMachineSidResult.IsFailed)
                {
                    _log.LogWarning("Failed to get machine sid for {Server}: {Status}. Abandoning URA collection",
                        computerName, getMachineSidResult.SError);
                    await SendComputerStatus(new CSVComputerStatus
                    {
                        ComputerName = computerName,
                        Status = getMachineSidResult.SError,
                        Task = "LSAGetMachineSID"
                    });
                    yield break;
                }

                machineSid = new SecurityIdentifier(getMachineSidResult.Value.Sid);
                Cache.AddMachineSid(computerObjectId, getMachineSidResult.Value.Sid);
            }
            else
            {
                machineSid = new SecurityIdentifier(temp);
            }

            foreach (var privilege in desiredPrivileges)
            {
                _log.LogTrace("Getting principals for privilege {Priv} on computer {ComputerName}", privilege, computerName);
                var ret = new UserRightsAssignmentAPIResult
                {
                    Collected = false,
                    Privilege = privilege
                };

                //Ask for all principals with the specified privilege. 
                var enumerateAccountsResult = await Task.Run(() => server.GetResolvedPrincipalsWithPrivilege(privilege)).TimeoutAfter(timeout);
                if (enumerateAccountsResult.IsFailed)
                {
                    _log.LogDebug(
                        "LSAEnumerateAccountsWithUserRight failed on {ComputerName} with status {Status} for privilege {Privilege}",
                        computerName, policyOpenResult.Error, privilege);
                    await SendComputerStatus(new CSVComputerStatus
                    {
                        ComputerName = computerName,
                        Status = enumerateAccountsResult.SError,
                        Task = "LSAEnumerateAccountsWithUserRight"
                    });
                    ret.FailureReason =
                        $"LSAEnumerateAccountsWithUserRights returned {enumerateAccountsResult.SError}";
                    yield return ret;
                    if (enumerateAccountsResult.IsTimeout) {
                        yield break;
                    }
                    continue;
                }

                await SendComputerStatus(new CSVComputerStatus
                {
                    ComputerName = computerName,
                    Status = CSVComputerStatus.StatusSuccess,
                    Task = "LSAEnumerateAccountsWithUserRight"
                });

                var resolved = new List<TypedPrincipal>();
                var names = new List<NamedPrincipal>();

                foreach (var value in enumerateAccountsResult.Value)
                {
                    var (sid, name, use, _) = value;
                    _log.LogTrace("Got principal {Name} with sid {SID} and use {Use} for privilege {Priv} on computer {ComputerName}", name, sid.Value, use, privilege, computerName);
                    //Check if our sid is filtered
                    if (Helpers.IsSidFiltered(sid.Value))
                        continue;

                    if (isDomainController)
                    {
                        var result = await ResolveDomainControllerPrincipal(sid.Value, computerDomain);
                        if (result != null)
                            resolved.Add(result);
                        continue;
                    }

                    //If we get a local well known principal, we need to convert it using the computer's domain sid
                    if (await _utils.ConvertLocalWellKnownPrincipal(sid, computerObjectId, computerDomain) is (true, var principal))
                    {
                        _log.LogTrace("Got Well Known Principal {SID} on computer {Computer} for privilege {Privilege} and type {Type}", principal.ObjectIdentifier, computerName, privilege, principal.ObjectType);
                        resolved.Add(principal);
                        continue;
                    }

                    //If the security identifier starts with the machine sid, we need to resolve it as a local account
                    if (sid.IsEqualDomainSid(machineSid))
                    {
                        _log.LogTrace("Got local account {sid} on computer {Computer} for privilege {Privilege}", sid.Value, computerName, privilege);
                        var objectType = use switch
                        {
                            SharedEnums.SidNameUse.User => Label.LocalUser,
                            SharedEnums.SidNameUse.Group => Label.LocalGroup,
                            SharedEnums.SidNameUse.Alias => Label.LocalGroup,
                            _ => Label.Base
                        };

                        //Throw out local user accounts
                        if (objectType == Label.LocalUser)
                            continue;

                        //The local group sid is computer machine sid - group rid.
                        var groupRid = sid.Rid();
                        var newSid = $"{computerObjectId}-{groupRid}";
                        if (name != null)
                            names.Add(new NamedPrincipal
                            {
                                ObjectId = newSid,
                                PrincipalName = name
                            });

                        resolved.Add(new TypedPrincipal
                        {
                            ObjectIdentifier = newSid,
                            ObjectType = objectType
                        });
                        continue;
                    }

                    //If we get here, we most likely have a domain principal in a local group. Do a lookup
                    var resolvedPrincipal = await _utils.ResolveIDAndType(sid.Value, computerDomain);
                    if (resolvedPrincipal.Success) resolved.Add(resolvedPrincipal.Principal);
                }

                ret.Collected = true;
                ret.LocalNames = names.ToArray();
                ret.Results = resolved.ToArray();
                yield return ret;
            }
        }

        private async Task<TypedPrincipal> ResolveDomainControllerPrincipal(string sid, string computerDomain)
        {
            //If the server is a domain controller and we have a well known group, use the domain value
            if (await _utils.GetWellKnownPrincipal(sid, computerDomain) is (true, var wellKnown))
                return wellKnown;
            //Otherwise, do a domain lookup
            var domainPrinciple =  await _utils.ResolveIDAndType(sid, computerDomain);
            return domainPrinciple.Principal;
        }


        private async Task SendComputerStatus(CSVComputerStatus status)
        {
            if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
        }
    }
}