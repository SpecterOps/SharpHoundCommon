using System.Linq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using Xunit;

namespace CommonLibTest;

public class LdapProducerQueryGeneratorTest
{
    [Fact]
    public void GenerateDefaultPartitionParameters_Container_IncludesBuiltinDomainFilter()
    {
        var expectedFilter = new LdapFilter()
            .AddComputers()
            .AddDomains()
            .AddUsers()
            .AddContainers()
            .AddBuiltinDomains()
            .AddGPOs()
            .AddOUs()
            .AddGroups()
            .GetFilter();

        var result = LdapProducerQueryGenerator.GenerateDefaultPartitionParameters(CollectionMethod.Container);

        Assert.Equal(expectedFilter, result.Filter.GetFilter());
        Assert.Contains("(objectClass=builtinDomain)", result.Filter.GetFilter());
    }

    [Fact]
    public void GenerateConfigurationPartitionParameters_Site_IncludesSiteFiltersAndProperties()
    {
        var expectedFilter = new LdapFilter()
            .AddContainers()
            .AddConfiguration()
            .AddSitesContainer()
            .AddSites()
            .AddSiteServers()
            .AddSiteSubnets()
            .GetFilter();

        var result = LdapProducerQueryGenerator.GenerateConfigurationPartitionParameters(CollectionMethod.Site);

        Assert.Equal(expectedFilter, result.Filter.GetFilter());
        Assert.All(CommonProperties.SiteProps.Concat(CommonProperties.SiteServerProps).Concat(CommonProperties.SiteSubnetProps),
            attribute => Assert.Contains(attribute, result.Attributes));
        Assert.DoesNotContain("(objectclass=pKICertificateTemplate)", result.Filter.GetFilter());
        Assert.DoesNotContain("(objectClass=certificationAuthority)", result.Filter.GetFilter());
        Assert.DoesNotContain("(objectCategory=pKIEnrollmentService)", result.Filter.GetFilter());
        Assert.DoesNotContain("(objectClass=msPKI-Enterprise-Oid)", result.Filter.GetFilter());
    }

    [Fact]
    public void GenerateConfigurationPartitionParameters_CertServices_IncludesCertFiltersAndProperties()
    {
        var expectedFilter = new LdapFilter()
            .AddContainers()
            .AddConfiguration()
            .AddSitesContainer()
            .AddCertificateTemplates()
            .AddCertificateAuthorities()
            .AddEnterpriseCertificationAuthorities()
            .AddIssuancePolicies()
            .GetFilter();

        var result = LdapProducerQueryGenerator.GenerateConfigurationPartitionParameters(CollectionMethod.CertServices);

        Assert.Equal(expectedFilter, result.Filter.GetFilter());
        Assert.All(CommonProperties.CertAbuseProps, attribute => Assert.Contains(attribute, result.Attributes));
        Assert.DoesNotContain(LDAPProperties.ServerReference, result.Attributes);
        Assert.DoesNotContain("(objectClass=site)", result.Filter.GetFilter());
        Assert.DoesNotContain("(objectClass=server)", result.Filter.GetFilter());
        Assert.DoesNotContain("(objectClass=subnet)", result.Filter.GetFilter());
    }

    [Fact]
    public void GenerateConfigurationPartitionParameters_SiteAndCertServices_IncludesBothFilterSets()
    {
        var expectedFilter = new LdapFilter()
            .AddContainers()
            .AddConfiguration()
            .AddSitesContainer()
            .AddCertificateTemplates()
            .AddCertificateAuthorities()
            .AddEnterpriseCertificationAuthorities()
            .AddIssuancePolicies()
            .AddSites()
            .AddSiteServers()
            .AddSiteSubnets()
            .GetFilter();

        var result = LdapProducerQueryGenerator.GenerateConfigurationPartitionParameters(
            CollectionMethod.Site | CollectionMethod.CertServices);

        Assert.Equal(expectedFilter, result.Filter.GetFilter());
    }
}
