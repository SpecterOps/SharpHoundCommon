using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Processors;
using Xunit;

namespace CommonLibTest {
    public class DCRegistryProcessorTests {
        private const string CurrentVersionKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        private const string Target = "dc.test.local";

        private readonly Mock<IRegistryAccessor> _registryAccessor = new();
        private readonly DCRegistryProcessor _processor;

        public DCRegistryProcessorTests() {
            _processor = new DCRegistryProcessor(Mock.Of<ILdapUtils>(), _registryAccessor.Object);
        }

        [Fact]
        public void GetCurrentBuildNumber_ReturnsCollectedStringValue() {
            _registryAccessor
                .Setup(s => s.GetRegistryKeyData(Target, CurrentVersionKey, "CurrentBuildNumber"))
                .Returns(new RegistryResult {
                    Collected = true,
                    Value = "26100"
                });

            var result = _processor.GetCurrentBuildNumber(Target);

            Assert.True(result.Collected);
            Assert.Equal("26100", result.Value);
        }

        [Fact]
        public void GetCurrentBuildRevision_ReturnsCollectedIntegerValue() {
            _registryAccessor
                .Setup(s => s.GetRegistryKeyData(Target, CurrentVersionKey, "UBR"))
                .Returns(new RegistryResult {
                    Collected = true,
                    Value = 4946
                });

            var result = _processor.GetCurrentBuildRevision(Target);

            Assert.True(result.Collected);
            Assert.Equal(4946, result.Value);
        }

        [Fact]
        public void GetCurrentBuildRevision_PreservesCollectionFailure() {
            _registryAccessor
                .Setup(s => s.GetRegistryKeyData(Target, CurrentVersionKey, "UBR"))
                .Returns(new RegistryResult {
                    Collected = false,
                    FailureReason = "access denied"
                });

            var result = _processor.GetCurrentBuildRevision(Target);

            Assert.False(result.Collected);
            Assert.Equal("access denied", result.FailureReason);
        }
    }
}
