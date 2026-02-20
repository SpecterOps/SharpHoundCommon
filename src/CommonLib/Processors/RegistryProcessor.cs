using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundRPC.PortScanner;
using SharpHoundRPC.Registry;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors;

public class RegistryProcessor {
    public delegate Task ComputerStatusDelegate(CSVComputerStatus status);
    
    private readonly ILogger _log;
    private readonly IPortScanner _portScanner;
    private readonly IStrategyExecutor _registryCollector; 
    private readonly AdaptiveTimeout _registryAdaptiveTimeout = new(maxTimeout:TimeSpan.FromMinutes(2), Logging.LogProvider.CreateLogger(nameof(ReadRegistrySettings)));
    private readonly ICollectionStrategy<RegistryQueryResult, RegistryQuery>[] _strategies;
    private readonly RegistryQuery[] _queries;

    public RegistryProcessor(ILogger log, IStrategyExecutor registryCollector, string domain) {
        _log = log ?? Logging.LogProvider.CreateLogger("RegistryProcessor");
        _portScanner = new PortScanner();
        _registryCollector = registryCollector;
        
        _strategies = [
            // Higher priority at the top of the list
            new DotNetWmiRegistryStrategy(_portScanner, domain),
            new RemoteRegistryStrategy(_portScanner),
        ];

        _queries = [
            RegistryQuery.ForKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0")
                .WithValues([
                    "ClientAllowedNTLMServers",     // Network security: Restrict NTLM: Add remote server exceptions for NTLM authentication
                    "NtlmMinClientSec",             // Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
                    "NtlmMinServerSec",             // Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
                    "RestrictReceivingNTLMTraffic", // Network security: Restrict NTLM: Incoming NTLM traffic
                    "RestrictSendingNTLMTraffic",   // Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
                ]),

            RegistryQuery.ForKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa\")
                .WithValues([
                    "LMCompatibilityLevel",         // Network security: LAN Manager authentication level
                    "UseMachineId"                  // Network security: Allow Local System to use computer identity for NTLM
                ]),

            RegistryQuery.ForKey(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")
                .WithValues([
                    "EnableSecuritySignature",      // Microsoft network client: Digitally sign communications (if server agrees) 
                    "RequireSecuritySignature",     // Microsoft network client: Digitally sign communications (always)
                ])
        ];
    }

    public event ComputerStatusDelegate ComputerStatusEvent;

    public async Task<APIResult<RegistryData>> ReadRegistrySettings(string targetMachine) {
        var output = new RegistryData();

        try {
            var result = await _registryAdaptiveTimeout.ExecuteWithTimeout(async (_) => await _registryCollector
                .CollectAsync(targetMachine, _queries, _strategies)
                .ConfigureAwait(false));

            if (!result.IsSuccess) {
                return APIResult<RegistryData>.Failure($"Timeout when grabbing registry data from {targetMachine}");
            }

            var collectedData = result.Value;

            foreach (var attempt in collectedData.FailureAttempts ?? []) {
                _log.LogTrace("ReadRegistry failed on {ComputerName} using {Strategy}: {Error}", targetMachine, attempt.StrategyType.Name, attempt.FailureReason);
                await SendComputerStatus(new CSVComputerStatus
                {
                    Task = $"{nameof(ReadRegistrySettings)} - {attempt.StrategyType.Name}",
                    ComputerName = targetMachine,
                    Status = attempt.FailureReason
                });
            }
            
            if (!collectedData.WasSuccessful) {
                var msg = collectedData.FailureAttempts is null 
                    ? "Failed to read registry settings"
                    : string.Join("\n",
                        collectedData.FailureAttempts.Select(a => $"{a.StrategyType.Name}: {a.FailureReason ?? ""}"));
                
                return APIResult<RegistryData>.Failure(msg);
            }
            
            await SendComputerStatus(new CSVComputerStatus
            {
                Task = $"{nameof(ReadRegistrySettings)} - {_strategies[collectedData.FailureAttempts?.Count() ?? 0].GetType().Name}",
                ComputerName = targetMachine,
                Status = CSVComputerStatus.StatusSuccess
            });

            foreach (var key in collectedData.Results ?? []) {
                if (!key.ValueExists)
                    continue;

                var name = key.ValueName;
                switch (name) {
                    case "ClientAllowedNTLMServers":
                        output.ClientAllowedNTLMServers = (string[])key.Value;
                        break;
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
                        output.UseMachineId = Convert.ToUInt32(key.Value);
                        break;
                    case "RequireSecuritySignature":
                        output.RequireSecuritySignature = Convert.ToUInt32(key.Value);
                        break;
                    case "EnableSecuritySignature":
                        output.EnableSecuritySignature = Convert.ToUInt32(key.Value);
                        break;
                }
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

    private async Task SendComputerStatus(CSVComputerStatus status) {
        if (ComputerStatusEvent is not null) await ComputerStatusEvent.Invoke(status);
    }
}