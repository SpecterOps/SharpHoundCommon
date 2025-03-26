using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC.PortScanner;
using SharpHoundRPC.Registry;
using System;
using System.Linq;
using System.Threading.Tasks;
using static SharpHoundCommonLib.Helpers;

namespace SharpHoundCommonLib.Processors;

public class RegistryProcessor {
    private readonly ILogger _log;
    private readonly IPortScanner _portScanner;
    private readonly ICollectionStrategy<RegistryQueryResult, RegistryQuery>[] _strategies;
    private readonly RegistryQuery[] _queries;

    public RegistryProcessor(ILogger log, string domain) {
        _log = log ?? Logging.LogProvider.CreateLogger("RegistryProcessor");
        _portScanner = new PortScanner();
        _strategies = [
            // Higher priority at the top of the list
            new DotNetWmiRegistryStrategy(_portScanner, domain),
            new RemoteRegistryStrategy(_portScanner),
        ];

        _queries = [
            RegistryQuery.ForKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0")
                .WithValues([
                    "NtlmMinClientSec",
                    "NtlmMinServerSec",
                    "RestrictReceivingNTLMTraffic",
                    "RestrictSendingNTLMTraffic",
                ]),

            RegistryQuery.ForKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa\")
                .WithValues([
                    "LMCompatibilityLevel",
                    "UseMachineId"
                ]),

            RegistryQuery.ForKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
                .WithValues([
                    "RequireSecuritySignature",
                ])
        ];
    }

    public async Task<APIResult<RegistryData>> ReadRegistrySettings(string targetMachine) {
        var output = new RegistryData();

        try {
            var registryCollector = new StrategyExecutor();
            var collectedData = await registryCollector
                .CollectAsync(targetMachine, _queries, _strategies)
                .ConfigureAwait(false);

            foreach (var key in collectedData.Results ?? []) {
                if (!key.ValueExists)
                    continue;

                var name = key.ValueName;
                switch (name) {
                    case "NtlmMinClientSec":
                        output.NtlmMinClientSec = Convert.ToUInt32(key.Value);
                        break;
                    case "NtlmMinServerSec":
                        output.NtlmMinServerSec = Convert.ToUInt32(key.Value);
                        break;
                    case "RestrictSendingNTLMTraffic":
                        output.RestrictSendingNtlmTraffic = Convert.ToUInt32(key.Value);
                        break;
                    case "RestrictReceivingNTLMTraffic":
                        output.RestrictReceivingNtlmTraffic = Convert.ToUInt32(key.Value);
                        break;
                    case "LMCompatibilityLevel":
                        output.LmCompatibilityLevel = Convert.ToUInt32(key.Value);
                        break;
                    case "UseMachineId":
                        output.UseMachine = Convert.ToUInt32(key.Value);
                        break;
                    case "RequireSecuritySignature":
                        output.RequireSecuritySignature = Convert.ToUInt32(key.Value);
                        break;
                }
            }

            // If all strategies failed, need to report errors.
            if (collectedData.FailureAttempts.Count() == _strategies.Length) {
                string msg = string.Join("\n",
                    collectedData.FailureAttempts.Select(a => $"{a.StrategyType.Name}: {a.FailureReason ?? ""}"));
                return APIResult<RegistryData>.Failure(msg);
            }

            return APIResult<RegistryData>.Success(output);
        } catch (Exception ex) {
            _log.LogError(
                "Unhandled Registry Processor exception {0}: {1}",
                targetMachine,
                ex.ToString());

            return APIResult<RegistryData>.Failure(ex.ToString());
        }
    }
}