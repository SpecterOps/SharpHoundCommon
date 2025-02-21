using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Impersonate;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC;
using SharpHoundRPC.NetAPINative;

namespace SharpHoundCommonLib.Processors {
    public class ComputerSessionProcessor {
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);

        private static readonly Regex SidRegex = new(@"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$", RegexOptions.Compiled);
        private readonly string _currentUserName;
        private readonly ILogger _log;
        private readonly NativeMethods _nativeMethods;
        private readonly ILdapUtils _utils;
        private readonly bool _doLocalAdminSessionEnum;
        private readonly string _localAdminUsername;
        private readonly string _localAdminPassword;

        public ComputerSessionProcessor(ILdapUtils utils,
            NativeMethods nativeMethods = null, ILogger log = null, string currentUserName = null,
            bool doLocalAdminSessionEnum = false,
            string localAdminUsername = null, string localAdminPassword = null) {
            _utils = utils;
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _currentUserName = currentUserName ?? WindowsIdentity.GetCurrent().Name.Split('\\')[1];
            _log = log ?? Logging.LogProvider.CreateLogger("CompSessions");
            _doLocalAdminSessionEnum = doLocalAdminSessionEnum;
            _localAdminUsername = localAdminUsername;
            _localAdminPassword = localAdminPassword;
        }

        public event ComputerStatusDelegate ComputerStatusEvent;

        /// <summary>
        ///     Uses the NetSessionEnum Win32 API call to get network sessions from a remote computer.
        ///     These are usually from SMB share accesses or other network sessions of the sort
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerSid"></param>
        /// <param name="computerDomain"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        public async Task<SessionAPIResult> ReadUserSessions(string computerName, string computerSid,
            string computerDomain, TimeSpan timeout = default) {
            if (timeout == default) {
                timeout = TimeSpan.FromMinutes(2);
            }

            var ret = new SessionAPIResult();

            _log.LogDebug("Running NetSessionEnum for {ObjectName}", computerName);

            var result = await Task.Run(() => {
                NetAPIResult<IEnumerable<NetSessionEnumResults>> result;
                if (_doLocalAdminSessionEnum) {
                    // If we are authenticating using a local admin, we need to impersonate for this
                    using (new Impersonator(_localAdminUsername, ".", _localAdminPassword,
                               LogonType.LOGON32_LOGON_NEW_CREDENTIALS, LogonProvider.LOGON32_PROVIDER_WINNT50)) {
                        result = _nativeMethods.NetSessionEnum(computerName);
                    }

                    if (result.IsFailed) {
                        // Fall back to default User
                        _log.LogDebug(
                            "NetSessionEnum failed on {ComputerName} with local admin credentials: {Status}. Fallback to default user.",
                            computerName, result.Status);
                        result = _nativeMethods.NetSessionEnum(computerName);
                    }
                } else {
                    result = _nativeMethods.NetSessionEnum(computerName);
                }

                return result;
            }).TimeoutAfter(timeout);

            if (result.IsFailed) {
                await SendComputerStatus(new CSVComputerStatus {
                    Status = result.GetErrorStatus(),
                    Task = "NetSessionEnum",
                    ComputerName = computerName
                });
                _log.LogTrace("NetSessionEnum failed on {ComputerName}: {Status}", computerName, result.Status);
                ret.Collected = false;
                ret.FailureReason = result.Status.ToString();
                return ret;
            }

            _log.LogDebug("NetSessionEnum succeeded on {ComputerName}", computerName);
            await SendComputerStatus(new CSVComputerStatus {
                Status = CSVComputerStatus.StatusSuccess,
                Task = "NetSessionEnum",
                ComputerName = computerName
            });

            ret.Collected = true;
            var results = new List<Session>();

            foreach (var sesInfo in result.Value) {
                var username = sesInfo.Username;
                var computerSessionName = sesInfo.ComputerName;

                _log.LogTrace("NetSessionEnum Entry: {Username}@{ComputerSessionName} from {ComputerName}", username,
                    computerSessionName, computerName);

                //Filter out blank/null cnames/usernames
                if (string.IsNullOrWhiteSpace(computerSessionName) || string.IsNullOrWhiteSpace(username)) {
                    continue;
                }

                //Filter out blank usernames, computer accounts, the user we're doing enumeration with, and anonymous logons
                if (username.EndsWith("$") ||
                    username.Equals(_currentUserName, StringComparison.CurrentCultureIgnoreCase) ||
                    username.Equals("anonymous logon", StringComparison.CurrentCultureIgnoreCase)) {
                    continue;
                }

                // Remove leading slashes for unc paths
                computerSessionName = computerSessionName.TrimStart('\\');

                string resolvedComputerSID = null;
                //Resolve "localhost" equivalents to the computer sid
                if (computerSessionName is "[::1]" or "127.0.0.1")
                    resolvedComputerSID = computerSid;
                else if (await _utils.ResolveHostToSid(computerSessionName, computerDomain) is (true, var tempSid))
                    //Attempt to resolve the host name to a SID
                    resolvedComputerSID = tempSid;

                //Throw out this data if we couldn't resolve it successfully. 
                if (resolvedComputerSID == null || !resolvedComputerSID.StartsWith("S-1")) {
                    continue;
                }

                var (matchSuccess, sids) = await _utils.GetGlobalCatalogMatches(username, computerDomain);
                if (matchSuccess) {
                    results.AddRange(
                        sids.Select(s => new Session { ComputerSID = resolvedComputerSID, UserSID = s }));
                } else {
                    var res = await _utils.ResolveAccountName(username, computerDomain);
                    if (res.Success)
                        results.Add(new Session {
                            ComputerSID = resolvedComputerSID,
                            UserSID = res.Principal.ObjectIdentifier
                        });
                }
            }

            ret.Results = results.ToArray();

            return ret;
        }

        /// <summary>
        ///     Uses the privileged win32 API, NetWkstaUserEnum, to return the logged on users on a remote computer.
        ///     Requires administrator rights on the target system
        /// </summary>
        /// <param name="computerName"></param>
        /// <param name="computerSamAccountName"></param>
        /// <param name="computerSid"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        public async Task<SessionAPIResult> ReadUserSessionsPrivileged(string computerName,
            string computerSamAccountName, string computerSid, TimeSpan timeout = default) {
            var ret = new SessionAPIResult();
            if (timeout == default) {
                timeout = TimeSpan.FromMinutes(2);
            }

            _log.LogDebug("Running NetWkstaUserEnum for {ObjectName}", computerName);

            var result = await Task.Run(() => {
                NetAPIResult<IEnumerable<NetWkstaUserEnumResults>>
                    result;
                if (_doLocalAdminSessionEnum) {
                    // If we are authenticating using a local admin, we need to impersonate for this
                    using (new Impersonator(_localAdminUsername, ".", _localAdminPassword,
                               LogonType.LOGON32_LOGON_NEW_CREDENTIALS, LogonProvider.LOGON32_PROVIDER_WINNT50)) {
                        result = _nativeMethods.NetWkstaUserEnum(computerName);
                    }

                    if (result.IsFailed) {
                        // Fall back to default User
                        _log.LogDebug(
                            "NetWkstaUserEnum failed on {ComputerName} with local admin credentials: {Status}. Fallback to default user.",
                            computerName, result.Status);
                        result = _nativeMethods.NetWkstaUserEnum(computerName);
                    }
                } else {
                    result = _nativeMethods.NetWkstaUserEnum(computerName);
                }

                return result;
            }).TimeoutAfter(timeout);

            if (result.IsFailed) {
                await SendComputerStatus(new CSVComputerStatus {
                    Status = result.GetErrorStatus(),
                    Task = "NetWkstaUserEnum",
                    ComputerName = computerName
                });
                _log.LogTrace("NetWkstaUserEnum failed on {ComputerName}: {Status}", computerName, result.Status);
                ret.Collected = false;
                ret.FailureReason = result.Status.ToString();
                return ret;
            }

            _log.LogTrace("NetWkstaUserEnum succeeded on {ComputerName}", computerName);
            await SendComputerStatus(new CSVComputerStatus {
                Status = result.Status.ToString(),
                Task = "NetWkstaUserEnum",
                ComputerName = computerName
            });

            ret.Collected = true;

            var results = new List<TypedPrincipal>();
            foreach (var wkstaUserInfo in result.Value) {
                var domain = wkstaUserInfo.LogonDomain;
                var username = wkstaUserInfo.Username;

                //If we dont have a domain or the domain has a space, ignore this object as it's unusable for us
                if (string.IsNullOrWhiteSpace(domain) || domain.Contains(" ")) {
                    continue;
                }

                //These are local computer accounts.
                if (domain.Equals(computerSamAccountName, StringComparison.CurrentCultureIgnoreCase)) {
                    continue;
                }

                //Filter out empty usernames and computer sessions
                if (string.IsNullOrWhiteSpace(username) || username.EndsWith("$", StringComparison.Ordinal)) {
                    continue;
                }

                if (await _utils.ResolveAccountName(username, domain) is (true, var res)) {
                    results.Add(res);
                }
            }

            ret.Results = results.Select(x => new Session {
                ComputerSID = computerSid,
                UserSID = x.ObjectIdentifier
            }).ToArray();

            return ret;
        }

        public async Task<SessionAPIResult> ReadUserSessionsRegistry(string computerName, string computerDomain,
            string computerSid) {
            var ret = new SessionAPIResult();

            _log.LogDebug("Running RegSessionEnum for {ObjectName}", computerName);

            RegistryKey key = null;

            try {
                var task = OpenRegistryKey(computerName, RegistryHive.Users);

                if (await Task.WhenAny(task, Task.Delay(10000)) != task) {
                    _log.LogDebug("Hit timeout on registry enum on {Server}. Abandoning registry enum", computerName);
                    ret.Collected = false;
                    ret.FailureReason = "Timeout";
                    await SendComputerStatus(new CSVComputerStatus {
                        Status = "Timeout",
                        Task = "RegistrySessionEnum",
                        ComputerName = computerName
                    });
                    return ret;
                }

                key = task.Result;

                ret.Collected = true;
                await SendComputerStatus(new CSVComputerStatus {
                    Status = CSVComputerStatus.StatusSuccess,
                    Task = "RegistrySessionEnum",
                    ComputerName = computerName
                });
                _log.LogTrace("Registry session enum succeeded on {ComputerName}", computerName);
                var results = new List<Session>();
                foreach (var subkey in key.GetSubKeyNames()) {
                    if (!SidRegex.IsMatch(subkey)) {
                        continue;
                    }

                    if (await _utils.ResolveIDAndType(subkey, computerDomain) is (true, var principal)) {
                        results.Add(new Session() {
                            ComputerSID = computerSid,
                            UserSID = principal.ObjectIdentifier
                        });
                    }
                }

                ret.Results = results.ToArray();

                return ret;
            } catch (Exception e) {
                _log.LogTrace("Registry session enum failed on {ComputerName}: {Status}", computerName, e.Message);
                await SendComputerStatus(new CSVComputerStatus {
                    Status = e.Message,
                    Task = "RegistrySessionEnum",
                    ComputerName = computerName
                });
                ret.Collected = false;
                ret.FailureReason = e.Message;
                return ret;
            } finally {
                key?.Dispose();
            }
        }

        private static Task<RegistryKey> OpenRegistryKey(string computerName, RegistryHive hive) {
            return Task.Run(() => RegistryKey.OpenRemoteBaseKey(hive, computerName));
        }

        private async Task SendComputerStatus(CSVComputerStatus status) {
            if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
        }
    }
}