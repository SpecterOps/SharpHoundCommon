using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using Xunit;
using SharpHoundRPC.Registry;

namespace CommonLibTest 
{
    public class RegistryProcessorTest
    {
        private readonly Mock<ILogger<RegistryProcessor>> _mockLogger;
        private readonly Mock<IStrategyExecutor> _mockStrategyExecutor;
        private readonly RegistryProcessor _registryProcessor;

        private const string DomainName = "TEST.LOCAL";
        private const string TargetName = "target.test.local";
        
        private readonly List<CSVComputerStatus> _receivedCompStatuses = [];

        public RegistryProcessorTest() {
            _mockLogger = new Mock<ILogger<RegistryProcessor>>();
            _mockStrategyExecutor = new Mock<IStrategyExecutor>();
            _registryProcessor = new RegistryProcessor(_mockLogger.Object, _mockStrategyExecutor.Object, DomainName);

            _registryProcessor.ComputerStatusEvent += status => {
                _receivedCompStatuses.Add(status);
                return Task.CompletedTask;
            };
        }

        [Fact]
        public async Task RegistryProcessor_ReadRegistrySettings_CollectionFailed() {
            const string failureReason = "No such host is known.";
            var attempts = new List<StrategyResult<RegistryQueryResult>>
            {
                new(typeof(DotNetWmiRegistryStrategy))
                {
                    FailureReason = failureReason
                },
                new(typeof(RemoteRegistryStrategy))
                {
                    FailureReason = failureReason
                }
            };
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(
                    new StrategyExecutorResult<RegistryQueryResult> {
                        FailureAttempts = attempts,
                        WasSuccessful = false
                    }
                );
            
            var results = await _registryProcessor.ReadRegistrySettings(TargetName);

            //Validate result
            Assert.False(results.Collected);
            var expectedFailureReason = string.Join("\n", attempts.Select(a => $"{a.StrategyType.Name}: {failureReason}"));
            Assert.Equal(expectedFailureReason, results.FailureReason);
            
            //Validate logs
            VerifyFailureLog<DotNetWmiRegistryStrategy>(TargetName, failureReason);
            VerifyFailureLog<RemoteRegistryStrategy>(TargetName, failureReason);
            Assert.Equal(2, _receivedCompStatuses.Count);
            foreach (var attempt in attempts) {
                VerifyCompStatusLog($"{nameof(_registryProcessor.ReadRegistrySettings)} - {attempt.StrategyType.Name}", TargetName, failureReason);
            }
        }

        [WindowsOnlyFact]
        public async Task RegistryProcessor_ReadRegistrySettings_FirstStrategySuccessful() {
            const uint minClientSecValue = 536870912;
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(
                    new StrategyExecutorResult<RegistryQueryResult> {
                        Results = [
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "ClientAllowedNTLMServers", null, null, false),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec", minClientSecValue, RegistryValueKind.DWord, true)
                        ],
                        WasSuccessful = true,
                    }
                );
            
            var results = await _registryProcessor.ReadRegistrySettings(TargetName);
        
            //Validate result
            Assert.True(results.Collected);
            Assert.Null(results.Result.ClientAllowedNTLMServers);
            Assert.Equal(minClientSecValue, results.Result.NtlmMinClientSec);
            
            //Validate logs
            _mockLogger.VerifyNoLogs(LogLevel.Trace);
            const string task = $"{nameof(_registryProcessor.ReadRegistrySettings)} - {nameof(DotNetWmiRegistryStrategy)}";
            VerifyCompStatusLog(task, TargetName, CSVComputerStatus.StatusSuccess);
        }

        [WindowsOnlyFact]
        public async Task RegistryProcessor_ReadRegistrySettings_SecondStrategySuccessful() {
            const string failureReason = "No such host is known.";
            const uint minClientSecValue = 536870912;
            
            var attempts = new List<StrategyResult<RegistryQueryResult>>
            {
                new(typeof(DotNetWmiRegistryStrategy))
                {
                    FailureReason = failureReason
                }
            };
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(
                    new StrategyExecutorResult<RegistryQueryResult> {
                        FailureAttempts = attempts,
                        Results = [
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec", minClientSecValue, RegistryValueKind.DWord, true)
                        ],
                        WasSuccessful = true
                    }
                );
            
            var results = await _registryProcessor.ReadRegistrySettings(TargetName);

            //Validate result
            Assert.True(results.Collected);
            Assert.Equal(minClientSecValue, results.Result.NtlmMinClientSec);
            
            //Validate logs
            VerifyFailureLog<DotNetWmiRegistryStrategy>(TargetName, failureReason);
            Assert.Equal(2, _receivedCompStatuses.Count);
            VerifyCompStatusLog($"{nameof(_registryProcessor.ReadRegistrySettings)} - {attempts[0].StrategyType.Name}", TargetName, failureReason);
            const string task = $"{nameof(_registryProcessor.ReadRegistrySettings)} - {nameof(RemoteRegistryStrategy)}";
            VerifyCompStatusLog(task, TargetName, CSVComputerStatus.StatusSuccess);
        }

        [Fact]
        public async Task RegistryProcessor_ReadRegistrySettings_HandlesException() {
            var exception = new Exception("test exception");
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .Throws(exception);
            
            var results = await _registryProcessor.ReadRegistrySettings(TargetName);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal(results.FailureReason, exception.ToString());
            
            //Validate logs
            _mockLogger.VerifyLogContains(LogLevel.Error, $"Unhandled Registry Processor exception {TargetName}: {exception}");
            Assert.Empty(_receivedCompStatuses);
        }

        [WindowsOnlyFact]
        public async Task RegistryProcessor_ReadRegistrySettings_SetsAllValues() {
            var allowedServers = new[] {"server"};
            const uint keyValue = 1;
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(
                    new StrategyExecutorResult<RegistryQueryResult> {
                        Results = [
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "ClientAllowedNTLMServers", allowedServers, RegistryValueKind.MultiString, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec", keyValue, RegistryValueKind.DWord, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinServerSec", keyValue, RegistryValueKind.DWord, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictSendingNTLMTraffic", keyValue, RegistryValueKind.DWord, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "RestrictReceivingNTLMTraffic", keyValue, RegistryValueKind.DWord, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\", "LMCompatibilityLevel", keyValue, RegistryValueKind.DWord, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\", "UseMachineId", keyValue, RegistryValueKind.DWord, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", keyValue, RegistryValueKind.DWord, true),
                            new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature", keyValue, RegistryValueKind.DWord, true),
                        ],
                        WasSuccessful = true,
                    }
                );
            
            var results = await _registryProcessor.ReadRegistrySettings(TargetName);
        
            //Validate result
            Assert.True(results.Collected);
            Assert.Equal(allowedServers, results.Result.ClientAllowedNTLMServers);
            Assert.Equal(keyValue, results.Result.NtlmMinClientSec);
            Assert.Equal(keyValue, results.Result.NtlmMinServerSec);
            Assert.Equal(keyValue, results.Result.RestrictSendingNtlmTraffic);
            Assert.Equal(keyValue, results.Result.RestrictReceivingNtlmTraffic);
            Assert.Equal(keyValue, results.Result.LmCompatibilityLevel);
            Assert.Equal(keyValue, results.Result.UseMachineId);
            Assert.Equal(keyValue, results.Result.RequireSecuritySignature);
            Assert.Equal(keyValue, results.Result.EnableSecuritySignature);
            
            //Validate logs
            const string task = $"{nameof(_registryProcessor.ReadRegistrySettings)} - {nameof(DotNetWmiRegistryStrategy)}";
            VerifyCompStatusLog(task, TargetName, CSVComputerStatus.StatusSuccess);
        }
        
        [Fact]
        public async Task RegistryProcessor_ReadRegistrySettings_HandlesFailureWithNoAttempts() {
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(
                    new StrategyExecutorResult<RegistryQueryResult> {
                        WasSuccessful = false
                    }
                );
            
            var results = await _registryProcessor.ReadRegistrySettings(TargetName);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal("Failed to read registry settings", results.FailureReason);
            
            //Validate logs
            _mockLogger.VerifyNoLogs(LogLevel.Trace);
            Assert.Empty(_receivedCompStatuses);
        }

        private void VerifyFailureLog<TStrategy>(string target, string reason) {
            var expected = $"ReadRegistry failed on {target} using {typeof(TStrategy)}: {reason}"; 
            _mockLogger.VerifyLogContains(LogLevel.Trace, expected);
        }
        
        private void VerifyCompStatusLog(string task, string computerName, string status) {
            Assert.Contains(_receivedCompStatuses, 
                compStat => compStat.Task == task && 
                          compStat.ComputerName == computerName &&
                          compStat.Status == status );
        }
    }
}