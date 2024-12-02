using System.Collections.Generic;
using System.Linq;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;

namespace SharpHoundCommonLib;

public class LdapProducerQueryGenerator {
    public static GeneratedLdapParameters GenerateDefaultPartitionParameters(CollectionMethod methods) {
        var filter = new LdapFilter();
        var properties = new List<string>();
        
        properties.AddRange(CommonProperties.BaseQueryProps);
        properties.AddRange(CommonProperties.TypeResolutionProps);

        if (methods.HasFlag(CollectionMethod.ObjectProps) || methods.HasFlag(CollectionMethod.ACL) || methods.HasFlag(CollectionMethod.Container)) {
            filter = filter.AddComputers().AddDomains().AddUsers().AddContainers().AddGPOs().AddOUs().AddGroups();

            if (methods.HasFlag(CollectionMethod.Container)) {
                properties.AddRange(CommonProperties.ContainerProps);
            }

            if (methods.HasFlag(CollectionMethod.Group)) {
                properties.AddRange(CommonProperties.GroupResolutionProps);
            }

            if (methods.HasFlag(CollectionMethod.ACL)) {
                properties.AddRange(CommonProperties.ACLProps);
            }

            if (methods.HasFlag(CollectionMethod.ObjectProps)) {
                properties.AddRange(CommonProperties.ObjectPropsProps);
            }

            if (methods.IsComputerCollectionSet()) {
                properties.AddRange(CommonProperties.ComputerMethodProps);
            }

            if (methods.HasFlag(CollectionMethod.Trusts)) {
                properties.AddRange(CommonProperties.DomainTrustProps);
            }
            
            if (methods.HasFlag(CollectionMethod.GPOLocalGroup))
                properties.AddRange(CommonProperties.GPOLocalGroupProps);

            if (methods.HasFlag(CollectionMethod.SPNTargets))
                properties.AddRange(CommonProperties.SPNTargetProps);

            if (methods.HasFlag(CollectionMethod.DCRegistry))
                properties.AddRange(CommonProperties.ComputerMethodProps);

            if (methods.HasFlag(CollectionMethod.SPNTargets)) {
                properties.AddRange(CommonProperties.SPNTargetProps);
            }

            return new GeneratedLdapParameters {
                Filter = filter,
                Attributes = properties.Distinct().ToArray()
            };
        }

        if (methods.IsComputerCollectionSet()) {
            filter = filter.AddComputers();
            properties.AddRange(CommonProperties.ComputerMethodProps);
        }

        if (methods.HasFlag(CollectionMethod.Trusts)) {
            filter = filter.AddDomains();
            properties.AddRange(CommonProperties.ComputerMethodProps);
        }

        if (methods.HasFlag(CollectionMethod.SPNTargets)) {
            filter = filter.AddUsers(CommonFilters.NeedsSPN);
            properties.AddRange(CommonProperties.SPNTargetProps);
        }

        if (methods.HasFlag(CollectionMethod.GPOLocalGroup)) {
            filter = filter.AddOUs();
            properties.AddRange(CommonProperties.GPOLocalGroupProps);
        }

        if (methods.HasFlag(CollectionMethod.DCRegistry)) {
            filter = filter.AddComputers(CommonFilters.DomainControllers);
            properties.AddRange(CommonProperties.ComputerMethodProps);
        }
        
        if (methods.HasFlag(CollectionMethod.Group)) {
            filter = filter.AddGroups();
            properties.AddRange(CommonProperties.GroupResolutionProps);
        }
        
        return new GeneratedLdapParameters {
            Filter = filter,
            Attributes = properties.Distinct().ToArray()
        };
    }

    public static GeneratedLdapParameters GenerateConfigurationPartitionParameters(CollectionMethod methods) {
        var filter = new LdapFilter();
        var properties = new List<string>();
        
        properties.AddRange(CommonProperties.BaseQueryProps);
        properties.AddRange(CommonProperties.TypeResolutionProps);

        if (methods.HasFlag(CollectionMethod.ACL) || methods.HasFlag(CollectionMethod.ObjectProps) ||
            methods.HasFlag(CollectionMethod.Container) || methods.HasFlag(CollectionMethod.CertServices)) {
            filter = filter.AddContainers().AddConfiguration().AddCertificateTemplates().AddCertificateAuthorities()
                .AddEnterpriseCertificationAuthorities().AddIssuancePolicies();
            
            if (methods.HasFlag(CollectionMethod.ObjectProps))
            {
                properties.AddRange(CommonProperties.ObjectPropsProps);
            }

            if (methods.HasFlag(CollectionMethod.ACL)) {
                properties.AddRange(CommonProperties.ACLProps);
            }

            if (methods.HasFlag(CollectionMethod.Container)) {
                properties.AddRange(CommonProperties.ContainerProps);
            }

            if (methods.HasFlag(CollectionMethod.CertServices)) {
                properties.AddRange(CommonProperties.CertAbuseProps);
                properties.AddRange(CommonProperties.ObjectPropsProps);
                properties.AddRange(CommonProperties.ContainerProps);
                properties.AddRange(CommonProperties.ACLProps);
            }

            if (methods.HasFlag(CollectionMethod.CARegistry)) {
                properties.AddRange(CommonProperties.CertAbuseProps);
            }

            return new GeneratedLdapParameters {
                Filter = filter,
                Attributes = properties.Distinct().ToArray()
            };
        }

        if (methods.HasFlag(CollectionMethod.CARegistry)) {
            filter = filter.AddEnterpriseCertificationAuthorities();
            properties.AddRange(CommonProperties.CertAbuseProps);
        }

        return new GeneratedLdapParameters {
            Filter = filter,
            Attributes = properties.Distinct().ToArray()
        };
    }
}

public class GeneratedLdapParameters {
    public string[] Attributes { get; set; }
    public LdapFilter Filter { get; set; }
}