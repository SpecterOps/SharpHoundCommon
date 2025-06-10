using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors {
    public class SPNProcessors {
        private const string MSSQLSPNString = "mssqlsvc";
        private readonly ILogger _log;
        private readonly ILdapUtils _utils;
        public delegate Task ComputerStatusDelegate(CSVComputerStatus status);
        public event ComputerStatusDelegate ComputerStatusEvent;

        public SPNProcessors(ILdapUtils utils, ILogger log = null) {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("SPNProc");
        }

        public IAsyncEnumerable<SPNPrivilege> ReadSPNTargets(ResolvedSearchResult result,
            IDirectoryObject entry) {
            if (entry.TryGetArrayProperty(LDAPProperties.ServicePrincipalNames, out var members)) {
                return ReadSPNTargets(members, result.Domain, result.DisplayName);
            }

            return AsyncEnumerable.Empty<SPNPrivilege>();
        }

        public async IAsyncEnumerable<SPNPrivilege> ReadSPNTargets(string[] servicePrincipalNames,
            string domainName, string objectName = "") {
            if (servicePrincipalNames.Length == 0) {
                _log.LogTrace("SPN Array is empty for {Name}", objectName);
                yield break;
            }
            
            _log.LogDebug("Processing SPN targets for {ObjectName}", objectName);

            foreach (var spn in servicePrincipalNames) {
                //This SPN format isn't useful for us right now (username@domain)
                if (spn.Contains("@")) {
                    _log.LogTrace("Skipping spn without @ {SPN} for {Name}", spn, objectName);
                    continue;
                }

                _log.LogTrace("Processing SPN {SPN} for {Name}", spn, objectName);

                if (spn.ToLower().Contains(MSSQLSPNString)) {
                    _log.LogTrace("Matched SQL SPN {SPN} for {Name}", spn, objectName);
                    var port = 1433;

                    if (spn.Contains(":"))
                        if (!int.TryParse(spn.Split(':')[1], out port))
                            port = 1433;

                    if (await _utils.ResolveHostToSid(spn, domainName) is (true, var host) && host.StartsWith("S-1")) {
                        _log.LogTrace("Resolved {SPN} to {Hostname}", spn, host);
                        await SendComputerStatus(new CSVComputerStatus {
                            Status = CSVComputerStatus.StatusSuccess,
                            Task = nameof(ReadSPNTargets),
                            ComputerName = spn,
                        });
                        yield return new SPNPrivilege {
                            ComputerSID = host,
                            Port = port,
                            Service = EdgeNames.SQLAdmin
                        };
                    }
                }
            }
        }
        
        private async Task SendComputerStatus(CSVComputerStatus status) {
            if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
        }
    }
}