using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Security.Principal;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.LDAPQueries;
using Xunit;

namespace CommonLibTest;

public class LdapDomainResolverTests {
    private const string DomainDn = "DC=child,DC=example,DC=test";
    private const string ConfigDn = "CN=Configuration,DC=example,DC=test";
    private const string DomainSid = "S-1-5-21-111-222-333";
    private const string ServerDn = "CN=DC\\, One,CN=Servers,CN=Site,CN=Sites," + ConfigDn;
    private const string RoleOwnerDn = "CN=NTDS Settings," + ServerDn;

    private static IDirectoryObject DomainRoot(byte[] sid = null, string owner = RoleOwnerDn) {
        if (sid == null) {
            var identifier = new SecurityIdentifier(DomainSid);
            sid = new byte[identifier.BinaryLength];
            identifier.GetBinaryForm(sid, 0);
        }
        var values = new Dictionary<string, object> { ["objectsid"] = sid };
        if (owner != null) values["fsmoroleowner"] = owner;
        return new SearchResultEntryWrapper(MockableSearchResultEntry.Construct(values, DomainDn));
    }

    private static IDirectoryObject Entry(params (string Name, object Value)[] attributes) =>
        new MockDirectoryObject("", attributes.ToDictionary(x => x.Name, x => x.Value,
            StringComparer.OrdinalIgnoreCase));

    private static IDirectoryObject Root() => Entry(
        ("defaultNamingContext", DomainDn),
        ("rootDomainNamingContext", "DC=example,DC=test"),
        ("configurationNamingContext", ConfigDn),
        ("schemaNamingContext", "CN=Schema," + ConfigDn));

    private sealed class FakeConnection : LdapDomainResolver.IConnection {
        internal readonly List<SearchRequest> Requests = new();
        internal Func<SearchRequest, IReadOnlyList<IDirectoryObject>> OnSearch = _ => new[] { Root() };
        internal Func<SearchRequest, (IReadOnlyList<IDirectoryObject> Entries, byte[] Cookie)> OnPage =
            _ => (Array.Empty<IDirectoryObject>(), Array.Empty<byte>());
        internal Exception BindFailure;
        internal bool Bound;
        internal bool Disposed;

        public void Bind() {
            Bound = true;
            if (BindFailure != null) throw BindFailure;
        }

        public IReadOnlyList<IDirectoryObject> Search(SearchRequest request) {
            Assert.True(Bound);
            Requests.Add(request);
            return OnSearch(request);
        }

        public IReadOnlyList<IDirectoryObject> SearchPage(SearchRequest request, out byte[] cookie) {
            Assert.True(Bound);
            Requests.Add(request);
            var page = OnPage(request);
            cookie = page.Cookie;
            return page.Entries;
        }

        public void Dispose() => Disposed = true;
    }

    private sealed class Harness {
        internal readonly Queue<FakeConnection> Connections = new();
        internal readonly List<(string Target, bool Ssl, bool Pinned)> Attempts = new();
        internal int EnvironmentReads;
        internal readonly LdapDomainResolver Resolver;

        internal Harness(LdapConfig config = null, string environmentDomain = null) {
            Resolver = new LdapDomainResolver(config ?? new LdapConfig(), (target, ssl, pinned) => {
                Attempts.Add((target, ssl, pinned));
                return Connections.Dequeue();
            }, () => {
                EnvironmentReads++;
                return environmentDomain;
            });
        }
    }

    [Theory]
    [InlineData("dc.example.test", "child.example.test", "credential.test", "other.test", "dc.example.test", true)]
    [InlineData("dc.example.test", null, "credential.test", "other.test", "dc.example.test", true)]
    [InlineData(null, "child.example.test", "credential.test", "other.test", "child.example.test", false)]
    [InlineData(" ", "child.example.test", null, "other.test", "child.example.test", false)]
    [InlineData(null, null, "child.example.test", "other.test", "child.example.test", false)]
    [InlineData(null, " ", " child.example.test ", "other.test", "child.example.test", false)]
    [InlineData(null, null, null, "child.example.test", "child.example.test", false)]
    [InlineData(null, null, "", "child.example.test", "child.example.test", false)]
    [InlineData(null, " ", " ", "other.test", "other.test", false)]
    public void TryResolve_SelectsEndpointInOrder(string server, string suppliedDomain, string userDomain,
        string environmentDomain, string expectedTarget, bool expectedPinned) {
        var harness = new Harness(new LdapConfig { Server = server, UserDomain = userDomain }, environmentDomain);
        var connection = new FakeConnection();
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve(suppliedDomain, out var domain));

        Assert.Equal("CHILD.EXAMPLE.TEST", domain.Name);
        Assert.Equal((expectedTarget, true, expectedPinned), Assert.Single(harness.Attempts));
        Assert.Equal(string.IsNullOrWhiteSpace(server) && string.IsNullOrWhiteSpace(suppliedDomain) &&
            string.IsNullOrWhiteSpace(userDomain) ? 1 : 0,
            harness.EnvironmentReads);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData("child.example.test")]
    [InlineData("child.example.test.")]
    [InlineData("CHILD")]
    public void TryResolve_UserDomainSupportsDnsAndNetBiosEndpointHints(string userDomain) {
        var config = new LdapConfig { UserDomain = userDomain };
        var harness = new Harness(config, "local.logon.test");
        var connection = new FakeConnection();
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve(null, out var domain));

        Assert.Equal("CHILD.EXAMPLE.TEST", domain.Name);
        Assert.Equal((userDomain, true, false), Assert.Single(harness.Attempts));
        Assert.Equal(0, harness.EnvironmentReads);
        Assert.Equal(3, connection.Requests.Count);
        Assert.Null(config.Username);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void TryResolve_NoTargetDoesNotCreateConnection(string environmentDomain) {
        var harness = new Harness(environmentDomain: environmentDomain);

        Assert.False(harness.Resolver.TryResolve(null, out var domain));
        Assert.Null(domain);
        Assert.Empty(harness.Attempts);
    }

    [Fact]
    public void TryResolve_TurkishCulturePreservesDomainAndForestDnsNames() {
        var originalCulture = CultureInfo.CurrentCulture;
        try {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
            var harness = new Harness();
            var connection = new FakeConnection {
                OnSearch = _ => new[] { Entry(("defaultNamingContext", DomainDn),
                    ("rootDomainNamingContext", "DC=initial,DC=test")) }
            };
            harness.Connections.Enqueue(connection);

            Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
            Assert.Equal("CHILD.EXAMPLE.TEST", domain.Name);
            Assert.Equal("INITIAL.TEST", domain.ForestName);
            Assert.True(connection.Disposed);
        }
        finally {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Theory]
    [InlineData(null, "child.example.test.", true)]
    [InlineData("dc.example.test", "child.example.test.", true)]
    [InlineData("dc.example.test", "ChIlD.ExAmPlE.TeSt.", true)]
    [InlineData("dc.example.test", "other.test.", false)]
    [InlineData("dc.example.test", "child.example.test..", false)]
    public void TryResolve_NormalizesOnlyTerminalDnsRootDot(string server, string suppliedDomain, bool expected) {
        var harness = new Harness(new LdapConfig { Server = server });
        var connection = new FakeConnection();
        harness.Connections.Enqueue(connection);

        Assert.Equal(expected, harness.Resolver.TryResolve(suppliedDomain, out var domain));
        if (expected) {
            Assert.Equal("CHILD.EXAMPLE.TEST", domain.Name);
        }
        else {
            Assert.Null(domain);
        }
        Assert.Equal((server ?? suppliedDomain, true, server != null), Assert.Single(harness.Attempts));
        Assert.Equal(expected ? 3 : 1, connection.Requests.Count);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void TryResolve_ReadsRootDseAndMaterializesNamingContexts() {
        var harness = new Harness();
        var connection = new FakeConnection();
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("ChIlD.ExAmPlE.TeSt", out var domain));

        var request = connection.Requests[0];
        Assert.Equal("", request.DistinguishedName);
        Assert.Equal(SearchScope.Base, request.Scope);
        Assert.Equal("(objectClass=*)", request.Filter);
        Assert.Equal(new[] { "defaultNamingContext", "rootDomainNamingContext", "configurationNamingContext",
            "schemaNamingContext" }, request.Attributes.Cast<string>());
        Assert.Empty(request.Controls);
        Assert.Equal(DomainDn, domain.DefaultNamingContext);
        Assert.Equal("EXAMPLE.TEST", domain.ForestName);
        Assert.Equal(ConfigDn, domain.ConfigurationNamingContext);
        Assert.Equal("CN=Schema," + ConfigDn, domain.SchemaNamingContext);
        Assert.Null(domain.DomainSid);
        Assert.Null(domain.PdcRoleOwnerName);
        Assert.Empty(domain.DomainControllerNames);
        Assert.Empty(domain.TrustTypes);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void TryResolve_MissingOptionalNamingContextsStillSucceeds() {
        var harness = new Harness();
        var connection = new FakeConnection { OnSearch = _ => new[] { Entry(("defaultNamingContext", DomainDn)) } };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain.ForestName);
        Assert.Null(domain.ConfigurationNamingContext);
        Assert.Null(domain.SchemaNamingContext);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("CN=Users")]
    [InlineData("DC=,DC=test")]
    public void TryResolve_MissingOrMalformedCoreDataFailsWithoutRetry(string defaultNamingContext) {
        var harness = new Harness();
        var connection = new FakeConnection {
            OnSearch = _ => new[] { defaultNamingContext == null ? Entry() :
                Entry(("defaultNamingContext", defaultNamingContext)) }
        };
        harness.Connections.Enqueue(connection);

        Assert.False(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain);
        Assert.Single(harness.Attempts);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void TryResolve_MultipleDefaultNamingContextsFailWithoutRetry() {
        var harness = new Harness();
        // The real wrapper reads the first value unless the resolver checks the count.
        var entry = MockableSearchResultEntry.Construct(new Dictionary<string, object> {
            ["defaultnamingcontext"] = DomainDn
        }, "");
        entry.Attributes["defaultNamingContext"].Add("DC=other,DC=test");
        var connection = new FakeConnection {
            OnSearch = _ => new IDirectoryObject[] { new SearchResultEntryWrapper(entry) }
        };
        harness.Connections.Enqueue(connection);

        Assert.False(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain);
        Assert.Single(harness.Attempts);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void TryResolve_MultipleNetBiosAliasesFailWithoutRetry() {
        var harness = new Harness();
        var entry = MockableSearchResultEntry.Construct(new Dictionary<string, object> {
            ["ncname"] = DomainDn,
            ["netbiosname"] = "CHILD"
        }, "");
        entry.Attributes["nETBIOSName"].Add("OTHER");
        var connection = new FakeConnection {
            OnSearch = request => request.Scope == SearchScope.Base ? new[] { Root() } :
                new IDirectoryObject[] { new SearchResultEntryWrapper(entry) }
        };
        harness.Connections.Enqueue(connection);

        Assert.False(harness.Resolver.TryResolve("CHILD", out var domain));
        Assert.Null(domain);
        Assert.Single(harness.Attempts);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void TryResolve_EmptyRootDseFailsAndDisposesConnection() {
        var harness = new Harness();
        var connection = new FakeConnection { OnSearch = _ => Array.Empty<IDirectoryObject>() };
        harness.Connections.Enqueue(connection);

        Assert.False(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void TryResolve_ConfiguredServerAdvertisingDifferentDnsDomainFailsWithoutRetry() {
        var harness = new Harness(new LdapConfig { Server = "dc.example.test" }, "child.example.test");
        var connection = new FakeConnection();
        harness.Connections.Enqueue(connection);

        Assert.False(harness.Resolver.TryResolve("other.test", out var domain));
        Assert.Null(domain);
        Assert.Equal(("dc.example.test", true, true), Assert.Single(harness.Attempts));
        Assert.Single(connection.Requests);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData("CHILD", DomainDn, true)]
    [InlineData("child", DomainDn, true)]
    [InlineData("OTHER", DomainDn, false)]
    [InlineData(null, DomainDn, false)]
    [InlineData("CHILD", "DC=other,DC=test", false)]
    public void TryResolve_ValidatesNetBiosAliasOnSameConnection(string alias, string crossRefDn, bool expected) {
        var harness = new Harness(new LdapConfig { Server = "dc.example.test" });
        var connection = new FakeConnection {
            OnSearch = request => request.Scope == SearchScope.Base ? new[] { Root() } :
                new[] { alias == null ? Entry(("nCName", crossRefDn)) :
                    Entry(("nCName", crossRefDn), ("nETBIOSName", alias)) }
        };
        harness.Connections.Enqueue(connection);

        Assert.Equal(expected, harness.Resolver.TryResolve("CHILD", out var domain));
        Assert.Equal(expected, domain != null);
        Assert.Equal(("dc.example.test", true, true), Assert.Single(harness.Attempts));
        Assert.Equal(expected ? 4 : 2, connection.Requests.Count);
        var request = connection.Requests[1];
        Assert.Equal("CN=Partitions," + ConfigDn, request.DistinguishedName);
        Assert.Equal(SearchScope.OneLevel, request.Scope);
        Assert.Equal("(&(objectClass=crossRef)(nCName=" + DomainDn + "))", request.Filter);
        Assert.Equal(new[] { "nCName", "nETBIOSName" }, request.Attributes.Cast<string>());
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TryResolve_NetBiosRequiresReadableCrossReference(bool missingConfiguration) {
        var harness = new Harness();
        var connection = new FakeConnection {
            OnSearch = request => request.Scope != SearchScope.Base ? Array.Empty<IDirectoryObject>() :
                new[] { missingConfiguration ? Entry(("defaultNamingContext", DomainDn)) : Root() }
        };
        harness.Connections.Enqueue(connection);

        Assert.False(harness.Resolver.TryResolve("CHILD", out var domain));
        Assert.Null(domain);
        Assert.Single(harness.Attempts);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void TryResolve_EscapesNamingContextInCrossReferenceFilter() {
        var harness = new Harness();
        var connection = new FakeConnection {
            OnSearch = request => request.Scope == SearchScope.Base ? new[] { Entry(
                ("defaultNamingContext", "DC=a*(b)\\c\0,DC=test"), ("configurationNamingContext", ConfigDn)) } :
                Array.Empty<IDirectoryObject>()
        };
        harness.Connections.Enqueue(connection);

        Assert.False(harness.Resolver.TryResolve("ALIAS", out _));
        Assert.Equal("(&(objectClass=crossRef)(nCName=DC=a\\2a\\28b\\29\\5cc\\00,DC=test))",
            connection.Requests[1].Filter);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TryResolve_LdapFailureRetriesSameEndpointAndDisposesBothConnections(bool failDuringBind) {
        var harness = new Harness(new LdapConfig { Server = "dc.example.test" });
        var failed = new FakeConnection();
        if (failDuringBind) failed.BindFailure = new LdapException(81);
        else failed.OnSearch = _ => throw new DirectoryOperationException("Test search failure");
        var success = new FakeConnection();
        harness.Connections.Enqueue(failed);
        harness.Connections.Enqueue(success);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.NotNull(domain);
        Assert.Equal(new[] { ("dc.example.test", true, true), ("dc.example.test", false, true) }, harness.Attempts);
        Assert.True(failed.Disposed);
        Assert.True(success.Disposed);
    }

    [Theory]
    [InlineData(false, 2)]
    [InlineData(true, 1)]
    public void TryResolve_ConnectionFailuresRespectForceSsl(bool forceSsl, int expectedAttempts) {
        var harness = new Harness(new LdapConfig { ForceSSL = forceSsl });
        var first = new FakeConnection { BindFailure = new LdapException(81) };
        var second = new FakeConnection { BindFailure = new LdapException(81) };
        harness.Connections.Enqueue(first);
        harness.Connections.Enqueue(second);

        Assert.False(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain);
        Assert.Equal(expectedAttempts, harness.Attempts.Count);
        Assert.True(first.Disposed);
        Assert.Equal(!forceSsl, second.Disposed);
    }

    [Fact]
    public void TryResolve_ConnectionConstructionFailureReturnsFailure() {
        var resolver = new LdapDomainResolver(new LdapConfig { ForceSSL = true },
            (_, _, _) => throw new LdapException(81), () => null);

        Assert.False(resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain);
    }

    [Fact]
    public void TryResolve_ReadsSidPdcAndControllerPagesOnConfiguredConnection() {
        // Convert a binary SID, resolve the PDC's parent server DN (including an escaped comma),
        // and collect controller pages without connecting to any discovered hostname.
        var harness = new Harness(new LdapConfig { Server = "pinned.example.test" });
        var page = 0;
        var connection = new FakeConnection {
            OnSearch = request => {
                if (request.DistinguishedName == "") return new[] { Root() };
                if (request.DistinguishedName == DomainDn) {
                    Assert.Equal(SearchScope.Base, request.Scope);
                    Assert.Equal(new[] { "objectSid", "fSMORoleOwner" }, request.Attributes.Cast<string>());
                    return new[] { DomainRoot() };
                }
                Assert.Equal(ServerDn, request.DistinguishedName);
                Assert.Equal(SearchScope.Base, request.Scope);
                Assert.Equal("(objectClass=server)", request.Filter);
                Assert.Equal(new[] { "dNSHostName" }, request.Attributes.Cast<string>());
                return new[] { Entry(("dNSHostName", "pdc.child.example.test")) };
            },
            OnPage = request => {
                Assert.Equal(DomainDn, request.DistinguishedName);
                Assert.Equal(SearchScope.Subtree, request.Scope);
                Assert.Equal(CommonFilters.DomainControllers, request.Filter);
                Assert.Equal(new[] { "dNSHostName" }, request.Attributes.Cast<string>());
                var control = Assert.IsType<PageResultRequestControl>(Assert.Single(request.Controls.Cast<DirectoryControl>()));
                Assert.Equal(500, control.PageSize);
                if (page++ == 0) {
                    Assert.Empty(control.Cookie);
                    return (new[] { Entry(("dNSHostName", "dc1.child.example.test")), Entry() }, new byte[] { 7, 9 });
                }
                // Carry the first page's cookie forward; ignore duplicates, missing names, and invalid hostnames.
                Assert.Equal(new byte[] { 7, 9 }, control.Cookie);
                return (new[] { Entry(("dNSHostName", "DC1.CHILD.EXAMPLE.TEST")),
                    Entry(("dNSHostName", " dc2.child.example.test ")), Entry(("dNSHostName", "bad host")) },
                    Array.Empty<byte>());
            }
        };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));

        Assert.Equal(DomainSid, domain.DomainSid);
        Assert.Equal("pdc.child.example.test", domain.PdcRoleOwnerName);
        Assert.Equal(new[] { "dc1.child.example.test", "dc2.child.example.test" }, domain.DomainControllerNames);
        Assert.Equal(2, page);
        Assert.Equal(("pinned.example.test", true, true), Assert.Single(harness.Attempts));
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData("root")]
    [InlineData("pdc")]
    [InlineData("controllers")]
    public void TryResolve_MetadataSearchFailuresPreserveOtherMetadataWithoutRetry(string failingRead) {
        // Fail each optional LDAP read independently: keep core identity and other available
        // metadata, dispose the connection, and avoid a new connection or plaintext retry.
        var harness = new Harness(new LdapConfig { Server = "pinned.example.test" });
        var connection = new FakeConnection {
            OnSearch = request => {
                if (request.DistinguishedName == "") return new[] { Root() };
                if (request.DistinguishedName == DomainDn) {
                    if (failingRead == "root") throw new LdapException(81);
                    return new[] { DomainRoot() };
                }
                if (failingRead == "pdc") throw new DirectoryOperationException("PDC lookup unavailable");
                return new[] { Entry(("dNSHostName", "pdc.child.example.test")) };
            },
            OnPage = _ => {
                if (failingRead == "controllers") throw new LdapException(81);
                return (new[] { Entry(("dNSHostName", "dc.child.example.test")) }, Array.Empty<byte>());
            }
        };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));

        Assert.Equal("CHILD.EXAMPLE.TEST", domain.Name);
        Assert.Equal(DomainDn, domain.DefaultNamingContext);
        Assert.Equal(failingRead == "root" ? null : DomainSid, domain.DomainSid);
        Assert.Equal(failingRead == "root" || failingRead == "pdc" ? null : "pdc.child.example.test", domain.PdcRoleOwnerName);
        Assert.Equal(failingRead == "controllers" ? Array.Empty<string>() : new[] { "dc.child.example.test" },
            domain.DomainControllerNames);
        Assert.Equal(("pinned.example.test", true, true), Assert.Single(harness.Attempts));
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TryResolve_MalformedSidPreservesPdcAndCoreIdentity(bool emptySid) {
        // Empty or truncated SID bytes leave only the SID unavailable; the PDC lookup still succeeds.
        var harness = new Harness();
        var connection = new FakeConnection {
            OnSearch = request => {
                if (request.DistinguishedName == "") return new[] { Root() };
                if (request.DistinguishedName == DomainDn) {
                    var sid = emptySid ? Array.Empty<byte>() : new byte[] { 1, 2 };
                    return new[] { DomainRoot(sid) };
                }
                return new[] { Entry(("dNSHostName", "pdc.child.example.test")) };
            }
        };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain.DomainSid);
        Assert.Equal("pdc.child.example.test", domain.PdcRoleOwnerName);
        Assert.Single(harness.Attempts);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("CN=NTDS Settings,")]
    [InlineData("not a distinguished name")]
    public void TryResolve_MissingOrMalformedRoleOwnerSkipsPdcLookup(string owner) {
        // Without a usable NTDS Settings parent DN, skip the PDC search while retaining the SID.
        var harness = new Harness();
        var connection = new FakeConnection {
            OnSearch = request => request.DistinguishedName == "" ? new[] { Root() } : new[] { DomainRoot(owner: owner) }
        };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Equal(DomainSid, domain.DomainSid);
        Assert.Null(domain.PdcRoleOwnerName);
        Assert.Equal(3, connection.Requests.Count);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public void TryResolve_UnavailableOrAmbiguousDomainRootLeavesMetadataEmpty(int count) {
        // Zero or multiple domain-root entries cannot supply reliable SID/PDC metadata,
        // but the identity already resolved from RootDSE remains valid.
        var harness = new Harness();
        var connection = new FakeConnection {
            OnSearch = request => request.DistinguishedName == "" ? new[] { Root() } :
                Enumerable.Range(0, count).Select(_ => DomainRoot()).ToArray()
        };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Null(domain.DomainSid);
        Assert.Null(domain.PdcRoleOwnerName);
        Assert.Empty(domain.DomainControllerNames);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("bad host")]
    public void TryResolve_UnavailableOrMalformedPdcHostnamePreservesSid(string hostname) {
        // A server object with no usable hostname leaves the PDC null without discarding the SID.
        var harness = new Harness();
        var connection = new FakeConnection {
            OnSearch = request => {
                if (request.DistinguishedName == "") return new[] { Root() };
                if (request.DistinguishedName == DomainDn) return new[] { DomainRoot() };
                if (hostname == null) return new[] { Entry() };
                return new[] { Entry(("dNSHostName", hostname)) };
            }
        };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Equal(DomainSid, domain.DomainSid);
        Assert.Null(domain.PdcRoleOwnerName);
        Assert.True(connection.Disposed);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TryResolve_IncompletePagingLeavesControllersEmptyWithoutRetry(bool missingControl) {
        // After a successful first page, a failed read or missing paging control must discard
        // partial controller results and preserve core success on the configured connection.
        var harness = new Harness(new LdapConfig { Server = "pinned.example.test" });
        var pages = 0;
        var connection = new FakeConnection {
            OnPage = _ => {
                if (pages++ == 0) return (new[] { Entry(("dNSHostName", "dc.child.example.test")) }, new byte[] { 1 });
                if (missingControl) return (new[] { Entry(("dNSHostName", "dc2.child.example.test")) }, null);
                throw new DirectoryOperationException("Later page unavailable");
            }
        };
        harness.Connections.Enqueue(connection);

        Assert.True(harness.Resolver.TryResolve("child.example.test", out var domain));
        Assert.Empty(domain.DomainControllerNames);
        Assert.Equal(2, pages);
        Assert.Equal(("pinned.example.test", true, true), Assert.Single(harness.Attempts));
        Assert.True(connection.Disposed);
    }
}
