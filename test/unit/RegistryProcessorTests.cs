using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
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
            
            var attempts = new List<StrategyResult<RegistryQueryResult>> {
                new(typeof(DotNetWmiRegistryStrategy)) {
                    FailureReason = failureReason
                },
                new(typeof(RemoteRegistryStrategy)) {
                    FailureReason = failureReason
                }
            };
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                FailureAttempts = attempts,
                WasSuccessful = false
            };
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(executorResult);
            
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

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task RegistryProcessor_ReadRegistrySettings_FirstStrategySuccessful() {
            const uint minClientSecValue = 536870912;
            
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                Results = [
                    new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "ClientAllowedNTLMServers", null, null, false),
                    new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec", minClientSecValue, RegistryValueKind.DWord, true)
                ],
                WasSuccessful = true,
                SuccessfulStrategy = typeof(DotNetWmiRegistryStrategy)
            };
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(executorResult);
            
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

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task RegistryProcessor_ReadRegistrySettings_SecondStrategySuccessful() {
            const string failureReason = "No such host is known.";
            const uint minClientSecValue = 536870912;
            
            var attempts = new List<StrategyResult<RegistryQueryResult>> {
                new(typeof(DotNetWmiRegistryStrategy)) {
                    FailureReason = failureReason
                }
            };
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                FailureAttempts = attempts,
                Results = [
                    new RegistryQueryResult(@"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NtlmMinClientSec", minClientSecValue, RegistryValueKind.DWord, true)
                ],
                WasSuccessful = true,
                SuccessfulStrategy = typeof(RemoteRegistryStrategy)
            };
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(executorResult);
            
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
            Assert.Equal(exception.ToString(), results.FailureReason);
            
            //Validate logs
            _mockLogger.VerifyLogContains(LogLevel.Error, $"Unhandled Registry Processor exception {TargetName}: {exception}");
            Assert.Empty(_receivedCompStatuses);
        }

        [SupportedOSPlatform("windows")]
        [WindowsOnlyFact]
        public async Task RegistryProcessor_ReadRegistrySettings_SetsAllValues() {
            var allowedServers = new[] {"server"};
            const uint keyValue = 1;

            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
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
                SuccessfulStrategy = typeof(DotNetWmiRegistryStrategy)
            };
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(executorResult);
            
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
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                WasSuccessful = false
            };
            
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(executorResult);
            
            var results = await _registryProcessor.ReadRegistrySettings(TargetName);

            //Validate result
            Assert.False(results.Collected);
            Assert.Equal("Failed to read registry settings", results.FailureReason);
            
            //Validate logs
            _mockLogger.VerifyNoLogs(LogLevel.Trace);
            Assert.Empty(_receivedCompStatuses);
        }

        [Fact]
        public async Task RegistryProcessor_ReadAzureRegistryData_SetsVmId() {
            const string vmId = "  A5EFCFA9-06E7-4A43-9D20-AB1C3F35B190  ";
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                Results = [
                    new RegistryQueryResult(
                        @"SOFTWARE\Microsoft\Windows Azure",
                        "VmId",
                        vmId,
                        null,
                        true)
                ],
                WasSuccessful = true,
                SuccessfulStrategy = typeof(DotNetWmiRegistryStrategy)
            };

            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    TargetName,
                    It.Is<IEnumerable<RegistryQuery>>(queries =>
                        queries.Single().KeyPath == @"SOFTWARE\Microsoft\Windows Azure" &&
                        queries.Single().ValueNames.Single() == "VmId"),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(executorResult);

            var result = await _registryProcessor.ReadAzureRegistryData(TargetName);

            Assert.True(result.Collected);
            Assert.Equal(vmId.Trim().ToLowerInvariant(), result.Result.VmId);
            _mockLogger.VerifyNoLogs(LogLevel.Warning);
            VerifyCompStatusLog(
                $"{nameof(_registryProcessor.ReadAzureRegistryData)} - {nameof(DotNetWmiRegistryStrategy)}",
                TargetName,
                CSVComputerStatus.StatusSuccess);
        }

        [Fact]
        public async Task RegistryProcessor_ReadAzureRegistryData_MissingVmIdIsSuccessful() {
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                Results = [
                    new RegistryQueryResult(
                        @"SOFTWARE\Microsoft\Windows Azure",
                        "VmId",
                        null,
                        null,
                        false)
                ],
                WasSuccessful = true,
                SuccessfulStrategy = typeof(DotNetWmiRegistryStrategy)
            };

            SetupRegistryCollection(executorResult);

            var result = await _registryProcessor.ReadAzureRegistryData(TargetName);

            Assert.True(result.Collected);
            Assert.Null(result.Result.VmId);
            _mockLogger.VerifyLogContains(LogLevel.Debug, "Azure VM ID registry value was not found");
            VerifyCompStatusLog(
                $"{nameof(_registryProcessor.ReadAzureRegistryData)} - {nameof(DotNetWmiRegistryStrategy)}",
                TargetName,
                CSVComputerStatus.StatusSuccess);
        }

        [Fact]
        public async Task RegistryProcessor_ReadAzureRegistryData_NoResultsIsSuccessful() {
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                WasSuccessful = true,
                SuccessfulStrategy = typeof(DotNetWmiRegistryStrategy)
            };

            SetupRegistryCollection(executorResult);

            var result = await _registryProcessor.ReadAzureRegistryData(TargetName);

            Assert.True(result.Collected);
            Assert.Null(result.Result.VmId);
            _mockLogger.VerifyLogContains(LogLevel.Debug, "Azure VM ID registry value was not found");
            VerifyCompStatusLog(
                $"{nameof(_registryProcessor.ReadAzureRegistryData)} - {nameof(DotNetWmiRegistryStrategy)}",
                TargetName,
                CSVComputerStatus.StatusSuccess);
        }

        [Fact]
        public async Task RegistryProcessor_ReadAzureRegistryData_CollectionFailed() {
            const string failureReason = "No such host is known.";
            var attempts = new List<StrategyResult<RegistryQueryResult>> {
                new(typeof(DotNetWmiRegistryStrategy)) { FailureReason = failureReason },
                new(typeof(RemoteRegistryStrategy)) { FailureReason = failureReason }
            };
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                FailureAttempts = attempts,
                WasSuccessful = false
            };

            SetupRegistryCollection(executorResult);

            var result = await _registryProcessor.ReadAzureRegistryData(TargetName);

            Assert.False(result.Collected);
            Assert.Equal(
                string.Join("\n", attempts.Select(attempt => $"{attempt.StrategyType.Name}: {failureReason}")),
                result.FailureReason);
            Assert.Equal(2, _receivedCompStatuses.Count);
            foreach (var attempt in attempts) {
                _mockLogger.VerifyLogContains(
                    LogLevel.Trace,
                    nameof(_registryProcessor.ReadAzureRegistryData),
                    TargetName,
                    attempt.StrategyType.Name,
                    failureReason);
                VerifyCompStatusLog(
                    $"{nameof(_registryProcessor.ReadAzureRegistryData)} - {attempt.StrategyType.Name}",
                    TargetName,
                    failureReason);
            }
        }

        [Fact]
        public async Task RegistryProcessor_ReadAzureRegistryData_SecondStrategySuccessful() {
            const string failureReason = "WMI unavailable";
            const string vmId = "a5efcfa9-06e7-4a43-9d20-ab1c3f35b190";
            var attempt = new StrategyResult<RegistryQueryResult>(typeof(DotNetWmiRegistryStrategy)) {
                FailureReason = failureReason
            };
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                FailureAttempts = [attempt],
                Results = [
                    new RegistryQueryResult(
                        @"SOFTWARE\Microsoft\Windows Azure",
                        "VmId",
                        vmId,
                        null,
                        true)
                ],
                WasSuccessful = true,
                SuccessfulStrategy = typeof(RemoteRegistryStrategy)
            };

            SetupRegistryCollection(executorResult);

            var result = await _registryProcessor.ReadAzureRegistryData(TargetName);

            Assert.True(result.Collected);
            Assert.Equal(vmId, result.Result.VmId);
            Assert.Equal(2, _receivedCompStatuses.Count);
            VerifyCompStatusLog(
                $"{nameof(_registryProcessor.ReadAzureRegistryData)} - {nameof(DotNetWmiRegistryStrategy)}",
                TargetName,
                failureReason);
            VerifyCompStatusLog(
                $"{nameof(_registryProcessor.ReadAzureRegistryData)} - {nameof(RemoteRegistryStrategy)}",
                TargetName,
                CSVComputerStatus.StatusSuccess);
        }

        [Fact]
        public async Task RegistryProcessor_ReadAzureRegistryData_HandlesFailureWithNoAttempts() {
            var executorResult = new StrategyExecutorResult<RegistryQueryResult> {
                WasSuccessful = false
            };

            SetupRegistryCollection(executorResult);

            var result = await _registryProcessor.ReadAzureRegistryData(TargetName);

            Assert.False(result.Collected);
            Assert.Equal("Failed to read the Azure Registry Data", result.FailureReason);
            _mockLogger.VerifyNoLogs(LogLevel.Trace);
            Assert.Empty(_receivedCompStatuses);
        }

        [Fact]
        public async Task RegistryProcessor_ReadAzureRegistryData_HandlesException() {
            var exception = new Exception("test exception");
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .Throws(exception);

            var result = await _registryProcessor.ReadAzureRegistryData(TargetName);

            Assert.False(result.Collected);
            Assert.Equal(exception.ToString(), result.FailureReason);
            _mockLogger.VerifyLogContains(
                LogLevel.Error,
                "Unhandled Azure registry read exception",
                TargetName);
            Assert.Empty(_receivedCompStatuses);
        }

        private void SetupRegistryCollection(StrategyExecutorResult<RegistryQueryResult> result) {
            _mockStrategyExecutor.Setup(se => se.CollectAsync(
                    It.IsAny<string>(),
                    It.IsAny<IEnumerable<RegistryQuery>>(),
                    It.IsAny<IEnumerable<ICollectionStrategy<RegistryQueryResult, RegistryQuery>>>()))
                .ReturnsAsync(result);
        }

        private void VerifyFailureLog<TStrategy>(string target, string reason) {
            var expected = $"ReadRegistry failed on {target} using {typeof(TStrategy).Name}: {reason}"; 
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
