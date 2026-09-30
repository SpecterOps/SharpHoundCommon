using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using CommonLibTest.Facades;
using Microsoft.Extensions.Logging;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest;

public class LdapDomainFallbackTests {
    private const string DomainName = "example.test";
    private const string DomainDn = "DC=example,DC=test";

    private sealed class Connection : LdapDomainResolver.IConnection {
        internal bool FailCore;
        internal bool FailMetadata;
        internal bool Disposed;

        public void Bind() { }

        public IReadOnlyList<IDirectoryObject> Search(SearchRequest request) {
            if (FailCore) throw new LdapException();
            if (request.DistinguishedName == "") {
                return new[] { new MockDirectoryObject("", new Dictionary<string, object> {
                    ["defaultNamingContext"] = DomainDn
                }) };
            }
            if (FailMetadata) throw new LdapException();
            return Array.Empty<IDirectoryObject>();
        }

        public IReadOnlyList<IDirectoryObject> SearchPage(SearchRequest request, out byte[] cookie) {
            if (FailMetadata) throw new LdapException();
            cookie = Array.Empty<byte>();
            return Array.Empty<IDirectoryObject>();
        }

        public void Dispose() => Disposed = true;
    }

    private sealed class LegacyDomain : LdapDomainResolver.ILegacyDomain {
        public string Name { get; set; } = DomainName;
        internal string NamingContext = DomainDn;
        internal bool FailCore;
        internal bool FailMetadata;
        internal int DisposeCalls;
        internal readonly Dictionary<string, string> NamingContexts = new();
        internal IReadOnlyList<string> Controllers = Array.Empty<string>();
        internal IReadOnlyDictionary<string, TrustType> Trusts = new Dictionary<string, TrustType>();
        internal string Forest;
        internal string Sid;
        internal string Pdc;

        public string DefaultNamingContext => FailCore ? throw new InvalidOperationException() : NamingContext;
        public string ForestName => ReadMetadata(Forest);
        public string DomainSid => ReadMetadata(Sid);
        public string PdcRoleOwnerName => ReadMetadata(Pdc);
        public string ReadNamingContext(string attribute) {
            NamingContexts.TryGetValue(attribute, out var value);
            return ReadMetadata(value);
        }
        public IReadOnlyList<string> ReadControllerNames() => ReadMetadata(Controllers);
        public IReadOnlyDictionary<string, TrustType> ReadTrustTypes() => ReadMetadata(Trusts);
        private T ReadMetadata<T>(T value) => FailMetadata ? throw new InvalidOperationException() : value;
        public void Dispose() => DisposeCalls++;
    }

    private static LdapDomainResolver CreateResolverWithoutEndpoint(
        Func<string, LdapDomainResolver.ILegacyDomain> getLegacyDomain) {
        return new LdapDomainResolver(new LdapConfig { AllowUncontrolledDomainFallback = true },
            (_, _, _) => throw new Xunit.Sdk.XunitException("No LDAP endpoint available"), () => null,
            getLegacyDomain: getLegacyDomain);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void ControlledSuccess_NeverInvokesFallback(bool enabled, bool failMetadata) {
        var connection = new Connection { FailMetadata = failMetadata };
        var resolver = new LdapDomainResolver(new LdapConfig { AllowUncontrolledDomainFallback = enabled },
            (_, _, _) => connection, () => null,
            getLegacyDomain: _ => throw new Xunit.Sdk.XunitException("Fallback must not be invoked"));

        Assert.True(resolver.TryResolveWithFallback(DomainName, out var domain, out var usedLegacy));

        Assert.False(usedLegacy);
        Assert.Equal("EXAMPLE.TEST", domain.Name);
        Assert.Null(domain.DomainSid);
        Assert.Empty(domain.DomainControllerNames);
        Assert.Empty(domain.TrustTypes);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void ControlledFailure_WithFlagOffNeverInvokesFallback() {
        var connection = new Connection { FailCore = true };
        var resolver = new LdapDomainResolver(new LdapConfig { ForceSSL = true },
            (_, _, _) => connection, () => null,
            getLegacyDomain: _ => throw new Xunit.Sdk.XunitException("Fallback must not be invoked"));

        Assert.False(resolver.TryResolveWithFallback(DomainName, out var domain, out var usedLegacy));

        Assert.Null(domain);
        Assert.False(usedLegacy);
        Assert.True(connection.Disposed);
    }

    [Fact]
    public void ControlledFailure_WithFlagOnMaterializesAndDisposesFallback() {
        var connection = new Connection { FailCore = true };
        var legacy = new LegacyDomain {
            Forest = "forest.test",
            Sid = "S-1-5-21-111-222-333",
            Pdc = "dc.example.test",
            NamingContexts = {
                ["configurationNamingContext"] = "CN=Configuration," + DomainDn,
                ["schemaNamingContext"] = "CN=Schema,CN=Configuration," + DomainDn
            },
            Controllers = new[] { "dc.example.test", "DC.EXAMPLE.TEST", null, " " },
            Trusts = new Dictionary<string, TrustType> {
                ["child.example.test"] = TrustType.ParentChild,
                ["other.test"] = TrustType.Forest
            }
        };
        var log = new Mock<ILogger<LdapUtils>>();
        var calls = 0;
        var resolver = new LdapDomainResolver(new LdapConfig { AllowUncontrolledDomainFallback = true },
            (_, _, _) => connection, () => null, log.Object, name => {
                Assert.True(connection.Disposed);
                Assert.Equal(DomainName, name);
                calls++;
                return legacy;
            });

        Assert.True(resolver.TryResolveWithFallback(DomainName, out var domain, out var usedLegacy));

        Assert.True(usedLegacy);
        Assert.Equal(1, calls);
        Assert.Equal(DomainName, domain.Name);
        Assert.Equal(DomainDn, domain.DefaultNamingContext);
        Assert.Equal("forest.test", domain.ForestName);
        Assert.Equal("S-1-5-21-111-222-333", domain.DomainSid);
        Assert.Equal("dc.example.test", domain.PdcRoleOwnerName);
        Assert.Equal("CN=Configuration," + DomainDn, domain.ConfigurationNamingContext);
        Assert.Equal("CN=Schema,CN=Configuration," + DomainDn, domain.SchemaNamingContext);
        Assert.Equal("dc.example.test", Assert.Single(domain.DomainControllerNames));
        Assert.Equal(TrustType.ParentChild, domain.TrustTypes["CHILD.EXAMPLE.TEST"]);
        Assert.Equal(TrustType.Forest, domain.TrustTypes["OTHER.TEST"]);
        Assert.Equal(1, legacy.DisposeCalls);
        log.VerifyLogContains(LogLevel.Warning, "Using uncontrolled framework domain fallback");
    }

    [Fact]
    public void FallbackMetadataFailures_PreserveCoreAndDisposeResource() {
        var legacy = new LegacyDomain { FailMetadata = true };
        var resolver = CreateResolverWithoutEndpoint(_ => legacy);

        Assert.True(resolver.TryResolveWithFallback(null, out var domain, out var usedLegacy));

        Assert.True(usedLegacy);
        Assert.Equal(DomainName, domain.Name);
        Assert.Null(domain.ForestName);
        Assert.Null(domain.DomainSid);
        Assert.Null(domain.PdcRoleOwnerName);
        Assert.Null(domain.ConfigurationNamingContext);
        Assert.Null(domain.SchemaNamingContext);
        Assert.Empty(domain.DomainControllerNames);
        Assert.Empty(domain.TrustTypes);
        Assert.Equal(1, legacy.DisposeCalls);
    }

    [Theory]
    [InlineData(null, DomainDn)]
    [InlineData(" ", DomainDn)]
    [InlineData(DomainName, null)]
    [InlineData(DomainName, "CN=Invalid")]
    public void FallbackMissingCore_ReturnsFailureAndDisposesResource(string name, string namingContext) {
        var legacy = new LegacyDomain { Name = name, NamingContext = namingContext };
        var resolver = CreateResolverWithoutEndpoint(_ => legacy);

        Assert.False(resolver.TryResolveWithFallback(null, out var domain, out var usedLegacy));

        Assert.True(usedLegacy);
        Assert.Null(domain);
        Assert.Equal(1, legacy.DisposeCalls);
    }

    [Fact]
    public void FallbackCoreReadThrows_ReturnsFailureAndDisposesResource() {
        var legacy = new LegacyDomain { FailCore = true };
        var resolver = CreateResolverWithoutEndpoint(_ => legacy);

        Assert.False(resolver.TryResolveWithFallback(null, out var domain, out _));

        Assert.Null(domain);
        Assert.Equal(1, legacy.DisposeCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FallbackCannotOpen_ReturnsFailure(bool throws) {
        var resolver = CreateResolverWithoutEndpoint(_ => throws ? throw new InvalidOperationException() : null);

        Assert.False(resolver.TryResolveWithFallback(null, out var domain, out var usedLegacy));

        Assert.True(usedLegacy);
        Assert.Null(domain);
    }
}
