using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using CommonLibTest.Facades;
using Microsoft.Extensions.Logging;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Ntlm;
using SharpHoundCommonLib.Processors;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class DCLdapProcessorTest : IDisposable {

        private readonly ITestOutputHelper _testOutputHelper;
        private readonly string SEC_E_UNSUPPORTED_FUNCTION = "80090302";
        private readonly string SEC_E_BAD_BINDINGS = "80090346";

        public DCLdapProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }

        [Fact]
        public async Task DCLdapProcessor_Scan() {
            var mockProcessor = new Mock<DCLdapProcessor>(10, "primary.testlab.local", null);

            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>(), null, null, It.IsAny<CancellationToken>())).ReturnsAsync(false);

            mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
            mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);

            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += status => {
                receivedStatus.Add(status);
                return Task.CompletedTask;
            };
            var results = await processor.Scan("primary.testlab.local", "");

            Assert.Equal(2, receivedStatus.Count);
            var status = receivedStatus[0];
            Assert.Equal(CSVComputerStatus.StatusSuccess, status.Status);
            status = receivedStatus[1];
            Assert.Equal(CSVComputerStatus.StatusSuccess, status.Status);
            Assert.True(results.HasLdap);
            Assert.True(results.HasLdaps);
            Assert.True(results.IsSigningRequired.Result);
            Assert.False(results.IsChannelBindingDisabled.Result);
        }

        [Fact]
        public async Task DCLdapProcessor_Scan_Failed() {
            var mockProcessor = new Mock<DCLdapProcessor>(10, "primary.testlab.local", null);

            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>(), null, null, It.IsAny<CancellationToken>())).Throws(new Exception("Error"));

            mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
            mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);

            var processor = mockProcessor.Object;
            var receivedStatus = new List<CSVComputerStatus>();
            processor.ComputerStatusEvent += status => {
                receivedStatus.Add(status);
                return Task.CompletedTask;
            };
            var results = await processor.Scan("primary.testlab.local", "");

            Assert.Equal(2, receivedStatus.Count);
            var status = receivedStatus[0];
            Assert.Contains("CheckIsNtlmSigningRequired failed: System.Exception: Error", status.Status);
            status = receivedStatus[1];
            Assert.Contains("CheckIsNtlmSigningRequired failed: System.Exception: Error", status.Status);
            Assert.True(results.HasLdap);
            Assert.True(results.HasLdaps);
            Assert.False(results.IsSigningRequired.Result);
            Assert.False(results.IsChannelBindingDisabled.Result);
            Assert.False(results.IsSigningRequired.Collected);
            Assert.False(results.IsChannelBindingDisabled.Collected);
        }

        // Obsolete by AdaptiveTimeout
        // [Fact]
        // public async Task DCLdapProcessor_CheckScan_Timeout() {
        //     var mockProcessor = new Mock<DCLdapProcessor>(2, "primary.testlab.local", null);

        //     mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>(), null, null, It.IsAny<CancellationToken>())).Returns(async () => {
        //         await Task.Delay(100);
        //         return false;
        //     });

        //     mockProcessor.Setup(x => x.TestLdapPort()).ReturnsAsync(true);
        //     mockProcessor.Setup(x => x.TestLdapsPort()).ReturnsAsync(true);

        //     var processor = mockProcessor.Object;
        //     var receivedStatus = new List<CSVComputerStatus>();
        //     processor.ComputerStatusEvent += status => {
        //         receivedStatus.Add(status);
        //         return Task.CompletedTask;
        //     };
        //     var results = await processor.Scan("primary.testlab.local");

        //     Assert.Equal(2, receivedStatus.Count);
        //     var status = receivedStatus[0];
        //     Assert.Equal("Timeout", status.Status);
        //     status = receivedStatus[1];
        //     Assert.Equal("Timeout", status.Status);
        //     Assert.Equal("Timeout", results.IsSigningRequired.FailureReason);
        //     Assert.Equal("Timeout", results.IsChannelBindingDisabled.FailureReason);
        // }

        [Fact]
        public async Task DCLdapProcessor_CheckIsNtlmSigningRequired() {
            var mockProcessor = new Mock<DCLdapProcessor>(10, "primary.testlab.local", null);
            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>(), null, null, It.IsAny<CancellationToken>())).ReturnsAsync(false);
            var processor = mockProcessor.Object;
            var result = await processor.CheckIsNtlmSigningRequired();
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task DCLdapProcessor_CheckIsNtlmSigningRequired_Exception() {
            var mockProcessor = new Mock<DCLdapProcessor>(10, "primary.testlab.local", null);
            mockProcessor.Setup(x => x.Authenticate(It.IsAny<Uri>(), It.IsAny<LdapAuthOptions>(), null, null, It.IsAny<CancellationToken>())).Throws(new Exception("Error"));
            var processor = mockProcessor.Object;
            var result = await processor.CheckIsNtlmSigningRequired();
            Assert.True(result.IsFailed);
            Assert.Contains("CheckIsNtlmSigningRequired failed: System.Exception: Error", result.Error);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_InvalidCredentialsException_SEC_E_UNSUPPORTED_FUNCTION() {
            var exception = "ErrorTest";
            var endpoint = "http://primary.testlab.local/";
            var expected = $"LDAP endpoint '{endpoint}' does not support NTLM";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Throws(new LdapNativeException("Error", (int)LdapErrorCodes.InvalidCredentials, SEC_E_UNSUPPORTED_FUNCTION));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), null, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLogContains(LogLevel.Debug, expected);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_InvalidCredentialsException_SEC_E_BAD_BINDINGS() {
            var exception = "ErrorTest";
            var endpoint = "http://primary.testlab.local/";
            var expected = $"Bad bindings with the LDAPS endpoint '{endpoint}'. Server error: {SEC_E_BAD_BINDINGS}";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Throws(new LdapNativeException("Error", (int)LdapErrorCodes.InvalidCredentials, SEC_E_BAD_BINDINGS));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), null, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLogContains(LogLevel.Debug, expected);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_InvalidCredentialsException_Unhandled() {
            var exception = "ErrorTest";
            var endpoint = "http://primary.testlab.local/";
            var expected = $"Unhandled LDAP InvalidCred error code during LDAP test: SharpHoundCommonLib.Ntlm.LdapNativeException: {exception}. LDAP error code: {(int)LdapErrorCodes.InvalidCredentials}.";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Throws(new LdapNativeException(exception, (int)LdapErrorCodes.InvalidCredentials, "80090347"));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), null, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLogContains(LogLevel.Error, expected);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_StrongAuthRequiredException() {
            var exception = "ErrorTest";
            var endpoint = "http://primary.testlab.local/";
            var expected = $"LDAP requires signing. Endpoint: {endpoint}";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Throws(new LdapNativeException(exception, (int)LdapErrorCodes.StrongAuthRequired, null));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), null, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLog(LogLevel.Debug, expected);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_ServerDownException() {
            var exception = "ErrorTest";
            var endpoint = "http://primary.testlab.local/";
            var expected = $"LDAP endpoint '{endpoint}' not accessible";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Throws(new LdapNativeException(exception, (int)LdapErrorCodes.ServerDown));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), null, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLog(LogLevel.Debug, expected);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_LdapUnhandledException() {
            var endpoint = "http://primary.testlab.local/";
            var exception = "ErrorTest";
            var expected = $"Unhandled LdapException error code during LDAP test: SharpHoundCommonLib.Ntlm.LdapNativeException: {exception}. LDAP error code: {(int)LdapErrorCodes.LocalError}";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Throws(new LdapNativeException(exception, (int)LdapErrorCodes.LocalError));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), null, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLogContains(LogLevel.Error, expected);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_InvalidOperationException() {
            var endpoint = "http://primary.testlab.local/";
            var exception = "Server did return a challenge";
            var expected = $"LDAP InvalidOperationException: {exception}";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            var mockAuthenticator = new Mock<NtlmAuthenticationHandler>(It.IsAny<string>(), null);
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Verifiable();
            mockAuthenticator.Setup(x => x.PerformNtlmAuthenticationAsync(It.IsAny<INtlmTransport>(), It.IsAny<CancellationToken>()))
                .Throws(new InvalidOperationException(exception));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), mockAuthenticator.Object, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLog(LogLevel.Debug, expected);
        }

        [Fact]
        public async Task DCLdapProcessor_Authenticate_UnhandledException() {
            var endpoint = "http://primary.testlab.local/";
            var exception = "Unhandled exception";
            var expected = $"An unhandled error occurred during the LDAP test: System.Exception: {exception}";

            var mockLogger = new Mock<ILogger<DCLdapProcessor>>();
            var mockLdapTransport = new Mock<LdapTransport>(null, It.IsAny<Uri>());
            var mockAuthenticator = new Mock<NtlmAuthenticationHandler>(It.IsAny<string>(), null);
            mockLdapTransport.Setup(x => x.InitializeConnectionAsync(It.IsAny<int>())).Verifiable();
            mockAuthenticator.Setup(x => x.PerformNtlmAuthenticationAsync(It.IsAny<INtlmTransport>(), It.IsAny<CancellationToken>()))
                .Throws(new Exception(exception));
            var processor = new DCLdapProcessor(10, "primary.testlab.local", mockLogger.Object);
            var result = await processor.Authenticate(new Uri(endpoint), It.IsAny<LdapAuthOptions>(), mockAuthenticator.Object, mockLdapTransport.Object);
            Assert.False(result);
            mockLogger.VerifyLogContains(LogLevel.Error, expected);
        }

    }
}