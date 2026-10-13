using System.Collections.Generic;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Models;
using Xunit;

namespace CommonLibTest;

public class LdapDomainInfoTests {
    [Fact]
    public void CoreIdentity_AllowsUnavailableAdditionalMetadata() {
        var domain = new LdapDomainInfo {
            Name = "example.test",
            DefaultNamingContext = "DC=example,DC=test"
        };

        Assert.Equal("example.test", domain.Name);
        Assert.Equal("DC=example,DC=test", domain.DefaultNamingContext);
        Assert.Null(domain.ForestName);
        Assert.Null(domain.DomainSid);
        Assert.Null(domain.ConfigurationNamingContext);
        Assert.Null(domain.SchemaNamingContext);
        Assert.Null(domain.PdcRoleOwnerName);
        Assert.Empty(domain.DomainControllerNames);
        Assert.Empty(domain.TrustTypes);
    }

    [Fact]
    public void TrustTypes_TargetNamesAreCaseInsensitive() {
        var domain = new LdapDomainInfo();
        domain.TrustTypes.Add("CHILD.EXAMPLE.TEST", TrustType.ParentChild);

        Assert.Equal(TrustType.ParentChild, domain.TrustTypes["child.example.test"]);
        domain.TrustTypes["Child.Example.Test"] = TrustType.CrossLink;
        Assert.Single(domain.TrustTypes);
        Assert.Equal(TrustType.CrossLink, domain.TrustTypes["CHILD.EXAMPLE.TEST"]);
    }

    [Fact]
    public void Collections_AreIndependentForEachResult() {
        var first = new LdapDomainInfo();
        var second = new LdapDomainInfo();
        first.DomainControllerNames.Add("dc.example.test");
        first.TrustTypes.Add("child.example.test", TrustType.ParentChild);

        Assert.Empty(second.DomainControllerNames);
        Assert.Empty(second.TrustTypes);
    }

    [Fact]
    public void PublicProperties_ExposeOnlyPlainMetadata() {
        foreach (var property in typeof(LdapDomainInfo).GetProperties()) {
            Assert.Contains(property.PropertyType, new[] {
                typeof(string), typeof(List<string>), typeof(Dictionary<string, TrustType>)
            });
        }
    }
}
