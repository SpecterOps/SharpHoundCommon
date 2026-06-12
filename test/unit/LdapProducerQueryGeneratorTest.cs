using System.Linq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using Xunit;

namespace CommonLibTest;

public class LdapProducerQueryGeneratorTest
{
    [Fact]
    public void GenerateConfigurationPartitionParameters_Site_IncludesSiteFiltersAndProperties()
    {
        var expectedFilter = new LdapFilter()
            .AddContainers()
            .AddConfiguration()
            .AddCertificateTemplates()
            .AddCertificateAuthorities()
            .AddEnterpriseCertificationAuthorities()
            .AddIssuancePolicies()
            .AddSites()
            .AddSiteServers()
            .AddSiteSubnets()
            .GetFilter();

        var result = LdapProducerQueryGenerator.GenerateConfigurationPartitionParameters(CollectionMethod.Site);

        Assert.Equal(expectedFilter, result.Filter.GetFilter());
        Assert.All(CommonProperties.SiteProps.Concat(CommonProperties.SiteServerProps).Concat(CommonProperties.SiteSubnetProps),
            attribute => Assert.Contains(attribute, result.Attributes));
    }
}
