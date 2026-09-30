using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Reflection;
using CommonLibTest.Facades;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Models;
using SharpHoundRPC.NetAPINative;
using System.Threading.Tasks;
using Xunit;

namespace CommonLibTest;

public class LdapUtilsDomainTests {
    private const string DomainName = "child.example.test";
    private const string DomainDn = "DC=child,DC=example,DC=test";
    private const string ConfigurationDn = "CN=Configuration,DC=example,DC=test";

    private sealed class Connection : LdapDomainResolver.IConnection {
        internal bool FailCore;
        internal bool IncludeMetadata;
        internal string ForestDn;
        internal bool Disposed;

        public void Bind() {
            if (FailCore) throw new LdapException();
        }

        public IReadOnlyList<IDirectoryObject> Search(SearchRequest request) {
            if (request.DistinguishedName != "") return Array.Empty<IDirectoryObject>();
            var attributes = new Dictionary<string, object> { ["defaultNamingContext"] = DomainDn };
            if (IncludeMetadata) {
                attributes["rootDomainNamingContext"] = "DC=example,DC=test";
                attributes["configurationNamingContext"] = ConfigurationDn;
                attributes["schemaNamingContext"] = "CN=Schema," + ConfigurationDn;
            }
            if (ForestDn != null) attributes["rootDomainNamingContext"] = ForestDn;
            return new[] { new MockDirectoryObject("", attributes) };
        }

        public IReadOnlyList<IDirectoryObject> SearchPage(SearchRequest request, out byte[] cookie) {
            cookie = Array.Empty<byte>();
            return Array.Empty<IDirectoryObject>();
        }

        public void Dispose() => Disposed = true;
    }

    private sealed class Harness {
        internal int ConnectionAttempts;
        internal bool FailCore;
        internal string ForestDn;
        internal readonly List<Connection> Connections = new();
        internal readonly List<string> Targets = new();
        internal readonly LegacyDomain Legacy = new();

        internal LdapUtils CreateUtils() => new(CreateResolver);

        internal LdapDomainResolver CreateResolver(LdapConfig config) => new(config, (target, _, _) => {
            ConnectionAttempts++;
            Targets.Add(target);
            var connection = new Connection { FailCore = FailCore, ForestDn = ForestDn };
            Connections.Add(connection);
            return connection;
        }, () => DomainName, getLegacyDomain: _ => Legacy);
    }

    private sealed class LegacyDomain : LdapDomainResolver.ILegacyDomain {
        internal int DisposeCalls;
        internal string Forest;
        public string Name => DomainName;
        public string DefaultNamingContext => DomainDn;
        public string ForestName => Forest;
        public string DomainSid => null;
        public string PdcRoleOwnerName => null;
        public string ReadNamingContext(string attribute) => null;
        public IReadOnlyList<string> ReadControllerNames() => Array.Empty<string>();
        public IReadOnlyDictionary<string, TrustType> ReadTrustTypes() => new Dictionary<string, TrustType>();
        public void Dispose() => DisposeCalls++;
    }

    [Fact]
    public void GetDomain_CachesControlledSuccessCaseInsensitively() {
        var harness = new Harness();
        using var utils = harness.CreateUtils();
        Assert.True(utils.GetDomain(DomainName, out var first));
        Assert.True(utils.GetDomain("  CHILD.EXAMPLE.TEST  ", out var second));
        Assert.Same(first, second);
        Assert.Equal(1, harness.ConnectionAttempts);
        Assert.True(Assert.Single(harness.Connections).Disposed);
        Assert.Null(first.DomainSid);
        Assert.Null(first.PdcRoleOwnerName);
        Assert.Empty(first.DomainControllerNames);
        Assert.Equal(0, harness.Legacy.DisposeCalls);
    }

    [Fact]
    public void GetDomain_DefaultOverloadsShareControlledCache() {
        var harness = new Harness();
        using var utils = harness.CreateUtils();
        Assert.True(utils.GetDomain(out var first));
        Assert.True(utils.GetDomain(null, out var second));
        Assert.True(utils.GetDomain(" ", out var third));
        Assert.Same(first, second);
        Assert.Same(first, third);
        Assert.Equal(1, harness.ConnectionAttempts);
    }

    [Fact]
    public void GetDomain_ConfigAndUtilsResetInvalidateCache() {
        var harness = new Harness();
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { Server = "first.example.test" });
        Assert.True(utils.GetDomain(out var first));
        utils.SetLdapConfig(new LdapConfig { Server = "second.example.test" });
        Assert.True(utils.GetDomain(out var second));
        utils.ResetUtils();
        Assert.True(utils.GetDomain(out var third));
        Assert.NotSame(first, second);
        Assert.NotSame(second, third);
        Assert.Equal(new[] { "first.example.test", "second.example.test", "second.example.test" }, harness.Targets);
    }

    [Fact]
    public void GetDomain_InstancesHaveIndependentCachesAndResets() {
        var harness = new Harness();
        using var firstUtils = harness.CreateUtils();
        using var secondUtils = harness.CreateUtils();
        Assert.True(firstUtils.GetDomain(DomainName, out var first));
        Assert.True(secondUtils.GetDomain(DomainName, out var second));
        Assert.NotSame(first, second);
        firstUtils.ResetUtils();
        Assert.True(secondUtils.GetDomain(DomainName, out var cached));
        Assert.Same(second, cached);
        Assert.Equal(2, harness.ConnectionAttempts);
    }

    [Fact]
    public void GetDomain_LegacySuccessIsRetriedAndNeverCached() {
        var harness = new Harness { FailCore = true };
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { AllowUncontrolledDomainFallback = true, ForceSSL = true });
        Assert.True(utils.GetDomain(DomainName, out var first));
        Assert.True(utils.GetDomain(DomainName, out var second));
        Assert.NotSame(first, second);
        Assert.Equal(2, harness.ConnectionAttempts);
        Assert.Equal(2, harness.Legacy.DisposeCalls);
        harness.FailCore = false;
        Assert.True(utils.GetDomain(DomainName, out _));
        Assert.Equal(3, harness.ConnectionAttempts);
        Assert.Equal(2, harness.Legacy.DisposeCalls);
    }

    [Fact]
    public void GetDomain_CoreFailureIsNotCachedOrPassedToLegacyByDefault() {
        var harness = new Harness { FailCore = true };
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { ForceSSL = true });
        Assert.False(utils.GetDomain(DomainName, out var failed));
        Assert.Null(failed);
        harness.FailCore = false;
        Assert.True(utils.GetDomain(DomainName, out _));
        Assert.Equal(2, harness.ConnectionAttempts);
        Assert.Equal(0, harness.Legacy.DisposeCalls);
    }

    [Fact]
    public async Task GetForest_ControlledMetadataRespectsInstanceAndConfiguration() {
        var firstHarness = new Harness { ForestDn = "DC=first,DC=test" };
        var secondHarness = new Harness { ForestDn = "DC=second,DC=test" };
        using var first = firstHarness.CreateUtils();
        using var second = secondHarness.CreateUtils();
        Assert.Equal((true, "FIRST.TEST"), await first.GetForest(DomainName));
        Assert.Equal((true, "SECOND.TEST"), await second.GetForest(DomainName));
        firstHarness.ForestDn = "DC=updated,DC=test";
        first.SetLdapConfig(new LdapConfig());
        Assert.Equal((true, "UPDATED.TEST"), await first.GetForest(DomainName));
    }

    [Fact]
    public async Task GetForest_LegacyMetadataIsNotCached() {
        var harness = new Harness { FailCore = true };
        harness.Legacy.Forest = "first.test";
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { AllowUncontrolledDomainFallback = true, ForceSSL = true });
        Assert.Equal((true, "FIRST.TEST"), await utils.GetForest(DomainName));
        harness.Legacy.Forest = "second.test";
        Assert.Equal((true, "SECOND.TEST"), await utils.GetForest(DomainName));
        Assert.Equal(2, harness.Legacy.DisposeCalls);
    }

    [Theory]
    [InlineData(NamingContext.Default, DomainDn)]
    [InlineData(NamingContext.Configuration, ConfigurationDn)]
    [InlineData(NamingContext.Schema, "CN=Schema," + ConfigurationDn)]
    public void PoolSearchBaseUsesAdvertisedForestRoot(NamingContext context, string expected) {
        var connection = new Connection { IncludeMetadata = true };
        var resolver = new LdapDomainResolver(new LdapConfig(), (_, _, _) => connection, () => null);
        // Force native discovery to fail so the default context also exercises LDAP resolution.
        var native = new Mock<NativeMethods>();
        native.Setup(x => x.CallDsGetDcName(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<uint>()))
            .Returns(NetAPIResult<NetAPIStructs.DomainControllerInfo>.Fail("No discovery result"));
        using var pool = new LdapConnectionPool(DomainName, DomainName, new LdapConfig(),
            nativeMethods: native.Object, domainResolver: resolver);
        var wrapper = new LdapConnectionWrapper(null, new MockDirectoryObject("", new Dictionary<string, object>()), false, DomainName);
        var parameters = new LdapQueryParameters {
            DomainName = DomainName, NamingContext = context, LDAPFilter = "(objectClass=*)",
            RelativeSearchBase = "CN=Container"
        };
        var result = CreatePoolSearchRequest(pool, parameters, wrapper);
        Assert.True(result.Success);
        Assert.Equal("CN=Container," + expected, result.Request.DistinguishedName);
        Assert.True(wrapper.GetSearchBase(context, out var saved));
        Assert.Equal(expected, saved);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(NamingContext.Configuration)]
    [InlineData(NamingContext.Schema)]
    public void PoolSearchBaseFailsWhenNamingContextIsUnavailable(NamingContext context) {
        var connection = new Connection();
        var resolver = new LdapDomainResolver(new LdapConfig(), (_, _, _) => connection, () => null);
        using var pool = new LdapConnectionPool(DomainName, DomainName, new LdapConfig(), domainResolver: resolver);
        var wrapper = new LdapConnectionWrapper(null, new MockDirectoryObject("", new Dictionary<string, object>()), false, DomainName);
        var result = CreatePoolSearchRequest(pool, new LdapQueryParameters {
            DomainName = DomainName, NamingContext = context, LDAPFilter = "(objectClass=*)"
        }, wrapper);
        Assert.False(result.Success);
        Assert.Null(result.Request);
        Assert.False(wrapper.GetSearchBase(context, out _));
    }

    private static (bool Success, SearchRequest Request) CreatePoolSearchRequest(LdapConnectionPool pool,
        LdapQueryParameters parameters, LdapConnectionWrapper wrapper) {
        var method = typeof(LdapConnectionPool).GetMethod("CreateSearchRequest", BindingFlags.Instance | BindingFlags.NonPublic,
            null, new[] { typeof(LdapQueryParameters), typeof(LdapConnectionWrapper) }, null);
        return ((bool, SearchRequest))method.Invoke(pool, new object[] { parameters, wrapper });
    }
}
