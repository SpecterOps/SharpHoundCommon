using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Linq;
using System.Threading;
using CommonLibTest.Facades;
using CommonLibTest.CollectionDefinitions;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Models;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundRPC.NetAPINative;
using System.Threading.Tasks;
using Xunit;

namespace CommonLibTest;

[Collection(nameof(CacheTestCollectionDefinition))]
public class LdapUtilsDomainTests {
    private const string DomainName = "child.example.test";
    private const string DomainDn = "DC=child,DC=example,DC=test";
    private const string ConfigurationDn = "CN=Configuration,DC=example,DC=test";

    private sealed class Connection : LdapDomainResolver.IConnection {
        internal bool FailCore;
        internal bool IncludeMetadata;
        internal string ForestDn;
        internal bool Disposed;
        internal Func<SearchRequest, IReadOnlyList<IDirectoryObject>> OnSearch;
        internal Func<SearchRequest, (IReadOnlyList<IDirectoryObject> Entries, byte[] Cookie)> OnPage;
        internal readonly List<SearchRequest> Requests = new();

        public void Bind() {
            if (FailCore) throw new LdapException();
        }

        public IReadOnlyList<IDirectoryObject> Search(SearchRequest request) {
            Requests.Add(request);
            if (OnSearch != null) return OnSearch(request);
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
            Requests.Add(request);
            if (OnPage != null) {
                var page = OnPage(request);
                cookie = page.Cookie;
                return page.Entries;
            }
            cookie = Array.Empty<byte>();
            return Array.Empty<IDirectoryObject>();
        }

        public void Dispose() => Disposed = true;
    }

    private sealed class Harness {
        internal int ConnectionAttempts;
        internal bool FailCore;
        internal string ForestDn;
        internal Action<Connection> ConfigureConnection;
        internal DateTime UtcNow = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        internal readonly List<Connection> Connections = new();
        internal readonly List<string> Targets = new();
        internal readonly LegacyDomain Legacy = new();

        internal LdapUtils CreateUtils() => new(CreateResolver, () => UtcNow);

        internal LdapDomainResolver CreateResolver(LdapConfig config) => new(config, (target, _, _) => {
            ConnectionAttempts++;
            Targets.Add(target);
            var connection = new Connection { FailCore = FailCore, ForestDn = ForestDn };
            ConfigureConnection?.Invoke(connection);
            Connections.Add(connection);
            return connection;
        }, () => DomainName, getLegacyDomain: _ => Legacy);
    }

    private sealed class LegacyDomain : LdapDomainResolver.ILegacyDomain {
        internal int DisposeCalls;
        internal bool FailCore;
        internal string CoreName = DomainName;
        internal string NamingContext = DomainDn;
        internal string FailingRead;
        internal string Forest;
        internal string Sid;
        internal string Pdc;
        internal readonly Dictionary<string, string> NamingContexts = new();
        internal IReadOnlyList<string> Controllers = Array.Empty<string>();
        internal IReadOnlyDictionary<string, TrustType> Trusts = new Dictionary<string, TrustType>();
        internal readonly Dictionary<string, int> ReadCounts = new();
        public string Name => CoreName;
        public string DefaultNamingContext => FailCore ? throw new InvalidOperationException() : NamingContext;
        public string ForestName => Read("forest", Forest);
        public string DomainSid => Read("sid", Sid);
        public string PdcRoleOwnerName => Read("pdc", Pdc);
        public string ReadNamingContext(string attribute) =>
            Read(attribute, NamingContexts.TryGetValue(attribute, out var value) ? value : null);
        public IReadOnlyList<string> ReadControllerNames() => Read("controllers", Controllers);
        public IReadOnlyDictionary<string, TrustType> ReadTrustTypes() => Read("trusts", Trusts);
        private T Read<T>(string metadata, T value) {
            ReadCounts.TryGetValue(metadata, out var count);
            ReadCounts[metadata] = count + 1;
            return FailingRead == metadata ? throw new InvalidOperationException("Metadata unavailable") : value;
        }
        public void Dispose() => DisposeCalls++;
    }

    private static IDirectoryObject Entry(string dn, params (string Name, object Value)[] attributes) =>
        new MockDirectoryObject(dn, attributes.ToDictionary(x => x.Name, x => x.Value));

    private static Harness CreateMetadataHarness(Func<string> failingRead = null,
        bool emptyMetadata = false, bool emptyTopology = false) {
        const string serverDn = "CN=DC,CN=Servers," + ConfigurationDn;
        const string forestRef = "CN=example.test,CN=Partitions," + ConfigurationDn;
        var harness = new Harness();
        harness.ConfigureConnection = connection => {
            var failure = failingRead?.Invoke();
            connection.OnSearch = request => {
                if (request.DistinguishedName == "") return new[] { Entry("",
                    ("defaultNamingContext", DomainDn), ("rootDomainNamingContext", "DC=example,DC=test"),
                    ("configurationNamingContext", ConfigurationDn)) };
                if (request.DistinguishedName == DomainDn) {
                    if (failure == "root") throw new LdapException(81);
                    if (emptyMetadata) return Array.Empty<IDirectoryObject>();
                    var owner = "CN=NTDS Settings," + serverDn;
                    if (failure == "sid") {
                        var root = new Mock<IDirectoryObject>();
                        root.Setup(x => x.TryGetSecurityIdentifier(out It.Ref<string>.IsAny))
                            .Throws(new InvalidOperationException("SID unavailable"));
                        root.Setup(x => x.PropertyCount("fSMORoleOwner")).Returns(1);
                        root.Setup(x => x.TryGetProperty("fSMORoleOwner", out owner)).Returns(true);
                        return new[] { root.Object };
                    }
                    return new[] { new MockDirectoryObject(DomainDn,
                        new Dictionary<string, object> { ["fSMORoleOwner"] = owner }, "S-1-5-21-111-222-333") };
                }
                if (failure == "pdc") throw new LdapException(81);
                return new[] { Entry(serverDn, ("dNSHostName", "pdc.child.example.test")) };
            };
            connection.OnPage = request => {
                var read = request.Filter.Equals(CommonFilters.TrustedDomains) ? "trusts" :
                    request.Scope == SearchScope.OneLevel ? "topology" : "controllers";
                if (failure == read) throw new LdapException(81);
                if (failure == "incomplete-" + read &&
                    request.Controls.OfType<PageResultRequestControl>().Single().Cookie.Length != 0) {
                    throw new DirectoryOperationException("Later page unavailable");
                }
                IDirectoryObject[] entries;
                if (emptyMetadata || read == "topology" && emptyTopology) entries = Array.Empty<IDirectoryObject>();
                else if (read == "controllers") entries = new[] { Entry("", ("dNSHostName", "dc.child.example.test")) };
                else if (read == "topology") entries = new[] {
                    Entry("CN=child.example.test,CN=Partitions," + ConfigurationDn,
                        ("nCName", DomainDn), ("trustParent", forestRef)),
                    Entry(forestRef, ("nCName", "DC=example,DC=test"))
                };
                else entries = new[] { Entry("", ("trustPartner", "example.test"),
                    ("trustType", 2), ("trustAttributes", (int)TrustAttributes.WithinForest)) };
                var cookie = failure == "missing-" + read ? null :
                    failure == "incomplete-" + read ? new byte[] { 1 } : Array.Empty<byte>();
                return (entries, cookie);
            };
        };
        return harness;
    }

    [Theory]
    [InlineData("root")]
    [InlineData("sid")]
    [InlineData("pdc")]
    [InlineData("controllers")]
    [InlineData("topology")]
    [InlineData("trusts")]
    [InlineData("incomplete-controllers")]
    [InlineData("incomplete-topology")]
    [InlineData("incomplete-trusts")]
    [InlineData("missing-controllers")]
    [InlineData("missing-topology")]
    [InlineData("missing-trusts")]
    public void GetDomain_RetriesFailedMetadataAfterBackoff(string failingRead) {
        var failure = failingRead;
        var harness = CreateMetadataHarness(() => failure);
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { Server = "pinned.example.test", ForceSSL = true });
        Assert.True(utils.GetDomain(DomainName, out var first));
        Assert.Equal(DomainName.ToUpperInvariant(), first.Name);
        Assert.Equal(DomainDn, first.DefaultNamingContext);
        if (failingRead == "root" || failingRead == "sid") Assert.Null(first.DomainSid);
        if (failingRead == "root" || failingRead == "pdc") Assert.Null(first.PdcRoleOwnerName);
        if (failingRead.EndsWith("controllers")) Assert.Empty(first.DomainControllerNames);
        if (failingRead.EndsWith("topology")) Assert.Equal(TrustType.Unknown, first.TrustTypes["example.test"]);
        if (failingRead.EndsWith("trusts")) Assert.Empty(first.TrustTypes);

        harness.UtcNow = harness.UtcNow.AddSeconds(29);
        Assert.True(utils.GetDomain(DomainName, out var beforeRetry));
        Assert.Same(first, beforeRetry);
        Assert.Equal(1, harness.ConnectionAttempts);

        harness.UtcNow = harness.UtcNow.AddSeconds(1);
        Assert.True(utils.GetDomain(DomainName, out var stillUnavailable));
        Assert.Equal(first.DomainSid, stillUnavailable.DomainSid);
        Assert.Equal(first.PdcRoleOwnerName, stillUnavailable.PdcRoleOwnerName);
        Assert.Equal(first.DomainControllerNames, stillUnavailable.DomainControllerNames);
        Assert.Equal(first.TrustTypes, stillUnavailable.TrustTypes);
        Assert.Equal(2, harness.ConnectionAttempts);
        failure = null;
        Assert.True(utils.GetDomain(DomainName, out var waiting));
        Assert.Same(stillUnavailable, waiting);
        Assert.Equal(2, harness.ConnectionAttempts);

        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        Assert.True(utils.GetDomain(DomainName, out var recovered));
        Assert.NotSame(first, recovered);
        Assert.Equal(first.Name, recovered.Name);
        Assert.Equal(first.DefaultNamingContext, recovered.DefaultNamingContext);
        Assert.Equal("S-1-5-21-111-222-333", recovered.DomainSid);
        Assert.Equal("pdc.child.example.test", recovered.PdcRoleOwnerName);
        Assert.Equal(new[] { "dc.child.example.test" }, recovered.DomainControllerNames);
        Assert.Equal(TrustType.ParentChild, recovered.TrustTypes["example.test"]);
        Assert.Equal(Enumerable.Repeat("pinned.example.test", 3), harness.Targets);
        Assert.All(harness.Connections, connection => Assert.True(connection.Disposed));

        // Recovery leaves the earlier snapshot intact and successful reads are not repeated.
        var retry = harness.Connections[2].Requests;
        Assert.Equal(failingRead == "root" || failingRead == "sid" || failingRead == "pdc",
            retry.Any(request => request.DistinguishedName == DomainDn && request.Scope == SearchScope.Base));
        Assert.Equal(failingRead == "root" || failingRead == "pdc",
            retry.Any(request => request.Attributes.Contains("dNSHostName") && request.Scope == SearchScope.Base));
        Assert.Equal(failingRead.EndsWith("controllers"),
            retry.Any(request => request.Attributes.Contains("dNSHostName") && request.Scope == SearchScope.Subtree));
        Assert.Equal(failingRead.EndsWith("topology"), retry.Any(request => request.Scope == SearchScope.OneLevel));
        Assert.Equal(failingRead.EndsWith("trusts"), retry.Any(request => request.Filter.Equals(CommonFilters.TrustedDomains)));
        if (failingRead.EndsWith("topology")) Assert.Equal(TrustType.Unknown, first.TrustTypes["example.test"]);
        if (failingRead.EndsWith("controllers")) Assert.Empty(first.DomainControllerNames);

        harness.UtcNow = harness.UtcNow.AddHours(1);
        Assert.True(utils.GetDomain(DomainName, out var cached));
        Assert.Same(recovered, cached);
        Assert.Equal(3, harness.ConnectionAttempts);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void GetDomain_SuccessfulEmptyOrUnknownMetadataDoesNotRetry(bool emptyMetadata) {
        var harness = CreateMetadataHarness(emptyMetadata: emptyMetadata, emptyTopology: true);
        using var utils = harness.CreateUtils();
        Assert.True(utils.GetDomain(DomainName, out var first));
        if (emptyMetadata) {
            Assert.Null(first.DomainSid);
            Assert.Null(first.PdcRoleOwnerName);
            Assert.Empty(first.DomainControllerNames);
            Assert.Empty(first.TrustTypes);
        }
        else Assert.Equal(TrustType.Unknown, first.TrustTypes["example.test"]);
        harness.UtcNow = harness.UtcNow.AddHours(1);
        Assert.True(utils.GetDomain(DomainName, out var cached));
        Assert.Same(first, cached);
        Assert.Equal(1, harness.ConnectionAttempts);
    }

    [Fact]
    public void GetDomain_RefreshConnectionFailurePreservesSnapshotAndBacksOffWithoutLegacyFallback() {
        string failure = "controllers";
        var harness = CreateMetadataHarness(() => failure);
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { ForceSSL = true, AllowUncontrolledDomainFallback = true });
        Assert.True(utils.GetDomain(DomainName, out var first));
        harness.FailCore = true;
        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        Assert.True(utils.GetDomain(DomainName, out var failedRefresh));
        Assert.Same(first, failedRefresh);
        Assert.Equal(2, harness.ConnectionAttempts);
        Assert.Equal(0, harness.Legacy.DisposeCalls);

        harness.FailCore = false;
        failure = null;
        Assert.True(utils.GetDomain(DomainName, out var waiting));
        Assert.Same(first, waiting);
        Assert.Equal(2, harness.ConnectionAttempts);
        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        Assert.True(utils.GetDomain(DomainName, out var recovered));
        Assert.Single(recovered.DomainControllerNames);
        Assert.Equal(first.DomainSid, recovered.DomainSid);
        Assert.Equal(first.PdcRoleOwnerName, recovered.PdcRoleOwnerName);
        Assert.Equal(first.TrustTypes, recovered.TrustTypes);
        Assert.Equal(3, harness.ConnectionAttempts);
    }

    [Fact]
    public void GetDomain_RefreshRejectsChangedIdentityAndPreservesSuccessfulMetadata() {
        string failure = "controllers";
        var harness = CreateMetadataHarness(() => failure);
        using var utils = harness.CreateUtils();
        Assert.True(utils.GetDomain(out var first));
        var configure = harness.ConfigureConnection;
        harness.ConfigureConnection = connection => {
            configure(connection);
            connection.OnSearch = _ => new[] { Entry("", ("defaultNamingContext", "DC=other,DC=test")) };
        };
        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        Assert.True(utils.GetDomain(out var cached));
        Assert.Same(first, cached);
        Assert.Equal(DomainName.ToUpperInvariant(), cached.Name);
        Assert.Equal(2, harness.ConnectionAttempts);
        Assert.Single(harness.Connections[1].Requests);
    }

    [Fact]
    public void GetDomain_AcceptsSingleLabelNameReturnedByDefaultResolution() {
        var harness = new Harness {
            ConfigureConnection = connection => connection.OnSearch = request => request.DistinguishedName == ""
                ? new[] { Entry("", ("defaultNamingContext", "DC=single")) }
                : Array.Empty<IDirectoryObject>()
        };
        using var utils = harness.CreateUtils();

        Assert.True(utils.GetDomain(out var first));
        Assert.Equal("SINGLE", first.Name);
        Assert.True(utils.GetDomain(first.Name, out var resolved));
        Assert.Equal(first.Name, resolved.Name);
        Assert.Equal(first.DefaultNamingContext, resolved.DefaultNamingContext);
        Assert.Equal(new[] { DomainName, "SINGLE" }, harness.Targets);
        Assert.All(harness.Connections, connection => {
            Assert.DoesNotContain(connection.Requests, request => request.Attributes.Contains("nETBIOSName"));
            Assert.True(connection.Disposed);
        });
    }

    [Fact]
    public void GetDomain_RefreshValidatesSingleLabelDnsIdentityWithoutNetBiosLookup() {
        string failure = "controllers";
        var harness = CreateMetadataHarness(() => failure);
        var configure = harness.ConfigureConnection;
        harness.ConfigureConnection = connection => {
            configure(connection);
            var search = connection.OnSearch;
            connection.OnSearch = request => request.DistinguishedName == ""
                ? new[] { Entry("", ("defaultNamingContext", "DC=single")) }
                : search(request);
        };
        using var utils = harness.CreateUtils();
        Assert.True(utils.GetDomain(out var first));
        failure = null;
        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        Assert.True(utils.GetDomain(out var recovered));
        Assert.Equal("SINGLE", recovered.Name);
        Assert.Equal(first.DefaultNamingContext, recovered.DefaultNamingContext);
        Assert.Single(recovered.DomainControllerNames);
        Assert.Equal(new[] { DomainName, DomainName }, harness.Targets);
        Assert.DoesNotContain(harness.Connections[1].Requests, request => request.Scope == SearchScope.OneLevel);
    }

    [Fact]
    public async Task GetDomain_ConcurrentCallsShareOneMetadataRefresh() {
        string failure = "controllers";
        var harness = CreateMetadataHarness(() => failure);
        using var utils = harness.CreateUtils();
        Assert.True(utils.GetDomain(DomainName, out var first));
        failure = null;
        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var configure = harness.ConfigureConnection;
        harness.ConfigureConnection = connection => {
            configure(connection);
            var readPage = connection.OnPage;
            connection.OnPage = request => {
                entered.Set();
                Assert.True(release.Wait(TimeSpan.FromSeconds(10)));
                return readPage(request);
            };
        };
        var refresh = Task.Run(() => {
            Assert.True(utils.GetDomain(DomainName, out var domain));
            return domain;
        });
        Task<LdapDomainInfo>[] callers;
        try {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));
            callers = Enumerable.Range(0, 8).Select(_ => Task.Run(() => {
                Assert.True(utils.GetDomain(DomainName, out var domain));
                return domain;
            })).ToArray();
        }
        finally {
            release.Set();
        }
        var recovered = await refresh;
        Assert.NotSame(first, recovered);
        Assert.Empty(first.DomainControllerNames);
        Assert.Single(recovered.DomainControllerNames);
        foreach (var domain in await Task.WhenAll(callers)) Assert.Same(recovered, domain);
        Assert.Equal(2, harness.ConnectionAttempts);
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
    public void GetDomain_CachesLegacySuccessCaseInsensitivelyUntilReset() {
        var harness = new Harness { FailCore = true };
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { AllowUncontrolledDomainFallback = true, ForceSSL = true });
        Assert.True(utils.GetDomain(DomainName, out var first));
        harness.UtcNow = harness.UtcNow.AddHours(1);
        Assert.True(utils.GetDomain("  CHILD.EXAMPLE.TEST  ", out var second));
        Assert.Same(first, second);
        Assert.Equal(1, harness.ConnectionAttempts);
        Assert.Equal(1, harness.Legacy.DisposeCalls);
        harness.FailCore = false;
        Assert.True(utils.GetDomain(DomainName, out var cached));
        Assert.Same(first, cached);
        Assert.Equal(1, harness.ConnectionAttempts);
        utils.ResetUtils();
        Assert.True(utils.GetDomain(DomainName, out var controlled));
        Assert.NotSame(first, controlled);
        Assert.Equal(2, harness.ConnectionAttempts);
        Assert.Equal(1, harness.Legacy.DisposeCalls);
    }

    [Theory]
    [InlineData("forest")]
    [InlineData("configurationNamingContext")]
    [InlineData("schemaNamingContext")]
    [InlineData("sid")]
    [InlineData("pdc")]
    [InlineData("controllers")]
    [InlineData("trusts")]
    public void GetDomain_CachedLegacyMetadataRetriesOnlyFailedReads(string failingRead) {
        var harness = new Harness { FailCore = true };
        var legacy = harness.Legacy;
        legacy.FailingRead = failingRead;
        legacy.Forest = "example.test";
        legacy.Sid = "S-1-5-21-111-222-333";
        legacy.Pdc = "pdc.child.example.test";
        legacy.NamingContexts["configurationNamingContext"] = ConfigurationDn;
        legacy.NamingContexts["schemaNamingContext"] = "CN=Schema," + ConfigurationDn;
        legacy.Controllers = new[] { "dc.child.example.test", "DC.CHILD.EXAMPLE.TEST" };
        legacy.Trusts = new Dictionary<string, TrustType> { ["example.test"] = TrustType.ParentChild };
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { AllowUncontrolledDomainFallback = true, ForceSSL = true });
        Assert.True(utils.GetDomain(DomainName, out var first));
        legacy.FailingRead = null;
        // Successful values remain cached even if the framework would now return other data.
        if (failingRead != "forest") legacy.Forest = "changed.test";
        harness.UtcNow = harness.UtcNow.AddSeconds(29);
        Assert.True(utils.GetDomain(DomainName, out var waiting));
        Assert.Same(first, waiting);
        Assert.Equal(1, legacy.DisposeCalls);
        harness.UtcNow = harness.UtcNow.AddSeconds(1);
        Assert.True(utils.GetDomain(DomainName, out var recovered));
        Assert.NotSame(first, recovered);
        Assert.Equal(first.Name, recovered.Name);
        Assert.Equal(first.DefaultNamingContext, recovered.DefaultNamingContext);
        Assert.Equal("example.test", recovered.ForestName);
        Assert.Equal(ConfigurationDn, recovered.ConfigurationNamingContext);
        Assert.Equal("CN=Schema," + ConfigurationDn, recovered.SchemaNamingContext);
        Assert.Equal("S-1-5-21-111-222-333", recovered.DomainSid);
        Assert.Equal("pdc.child.example.test", recovered.PdcRoleOwnerName);
        Assert.Equal("dc.child.example.test", Assert.Single(recovered.DomainControllerNames));
        Assert.Equal(TrustType.ParentChild, recovered.TrustTypes["example.test"]);
        if (failingRead == "forest") Assert.Null(first.ForestName);
        if (failingRead == "controllers") Assert.Empty(first.DomainControllerNames);
        if (failingRead == "trusts") Assert.Empty(first.TrustTypes);
        foreach (var read in legacy.ReadCounts) Assert.Equal(read.Key == failingRead ? 2 : 1, read.Value);
        Assert.Equal(2, legacy.DisposeCalls);
        Assert.Equal(1, harness.ConnectionAttempts);
        harness.UtcNow = harness.UtcNow.AddHours(1);
        Assert.True(utils.GetDomain(DomainName, out var cached));
        Assert.Same(recovered, cached);
        Assert.Equal(2, legacy.DisposeCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GetDomain_LegacyRefreshFailurePreservesSnapshotAndBacksOff(bool changedIdentity) {
        var harness = new Harness { FailCore = true };
        harness.Legacy.Forest = "example.test";
        harness.Legacy.FailingRead = "controllers";
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { AllowUncontrolledDomainFallback = true, ForceSSL = true });
        Assert.True(utils.GetDomain(DomainName, out var first));
        harness.Legacy.FailCore = !changedIdentity;
        if (changedIdentity) harness.Legacy.CoreName = "other.test";
        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        Assert.True(utils.GetDomain(DomainName, out var failedRefresh));
        Assert.Same(first, failedRefresh);
        Assert.Equal(2, harness.Legacy.DisposeCalls);
        harness.Legacy.FailCore = false;
        harness.Legacy.CoreName = DomainName;
        harness.Legacy.FailingRead = null;
        harness.Legacy.Controllers = new[] { "dc.child.example.test" };
        Assert.True(utils.GetDomain(DomainName, out var waiting));
        Assert.Same(first, waiting);
        Assert.Equal(2, harness.Legacy.DisposeCalls);
        harness.UtcNow = harness.UtcNow.AddSeconds(30);
        Assert.True(utils.GetDomain(DomainName, out var recovered));
        Assert.Single(recovered.DomainControllerNames);
        Assert.Equal(first.ForestName, recovered.ForestName);
        Assert.Empty(first.DomainControllerNames);
        Assert.Equal(3, harness.Legacy.DisposeCalls);
        Assert.Equal(1, harness.ConnectionAttempts);
    }

    [Fact]
    public void GetDomain_LegacyCoreFailureIsRetriedAndDisablingFallbackClearsCachedSuccess() {
        var harness = new Harness { FailCore = true };
        harness.Legacy.FailCore = true;
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { AllowUncontrolledDomainFallback = true, ForceSSL = true });
        Assert.False(utils.GetDomain(DomainName, out _));
        Assert.False(utils.GetDomain(DomainName, out _));
        harness.Legacy.FailCore = false;
        Assert.True(utils.GetDomain(DomainName, out _));
        Assert.Equal(3, harness.Legacy.DisposeCalls);
        Assert.Equal(3, harness.ConnectionAttempts);
        utils.SetLdapConfig(new LdapConfig { ForceSSL = true });
        Assert.False(utils.GetDomain(DomainName, out _));
        Assert.Equal(3, harness.Legacy.DisposeCalls);
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
    public async Task GetForest_LegacyMetadataIsCachedUntilReset() {
        var harness = new Harness { FailCore = true };
        harness.Legacy.Forest = "first.test";
        using var utils = harness.CreateUtils();
        utils.SetLdapConfig(new LdapConfig { AllowUncontrolledDomainFallback = true, ForceSSL = true });
        Assert.Equal((true, "FIRST.TEST"), await utils.GetForest(DomainName));
        harness.Legacy.Forest = "second.test";
        Assert.Equal((true, "FIRST.TEST"), await utils.GetForest(DomainName));
        Assert.Equal(1, harness.Legacy.DisposeCalls);
        utils.ResetUtils();
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
