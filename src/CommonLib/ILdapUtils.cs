using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib {
    public interface ILdapUtils : IDisposable {
        /// <summary>
        /// Performs a non-paged LDAP query. 
        /// </summary>
        /// <param name="queryParameters">Parameters for the LDAP query</param>
        /// <param name="cancellationToken">Optional cancellation token to support early exit</param>
        /// <returns>An IEnumerable containing Result objects containing Directory Objects</returns>
        IAsyncEnumerable<LdapResult<IDirectoryObject>> Query(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new());

        /// <summary>
        /// Performs a LDAP query with paging support. 
        /// </summary>
        /// <param name="queryParameters">Parameters for the LDAP query</param>
        /// <param name="cancellationToken">Optional cancellation token to support early exit</param>
        /// <returns>An IEnumerable containing Result objects containing Directory Objects</returns>
        IAsyncEnumerable<LdapResult<IDirectoryObject>> PagedQuery(LdapQueryParameters queryParameters,
            CancellationToken cancellationToken = new());

        /// <summary>
        /// Performs a ranged retrieval operation
        /// </summary>
        /// <param name="distinguishedName">The base distinguished name to search on</param>
        /// <param name="attributeName">The attribute being retrieved</param>
        /// <param name="cancellationToken">A cancellation token for early exit</param>
        /// <returns>An IEnumerable of result objects containing string results from the query</returns>
        IAsyncEnumerable<Result<string>> RangedRetrieval(string distinguishedName,
            string attributeName, CancellationToken cancellationToken = new());

        /// <summary>
        /// Attempts to resolve a SecurityIdentifier to its corresponding TypedPrincipal
        /// </summary>
        /// <param name="securityIdentifier">SecurityIdentifier object to resolve</param>
        /// <param name="objectDomain">The domain the object belongs too</param>
        /// <returns>A tuple containing success state as well as the resolved principal if successful</returns>
        Task<(bool Success, TypedPrincipal Principal)> ResolveIDAndType(SecurityIdentifier securityIdentifier,
            string objectDomain);

        /// <summary>
        /// Attempts to resolve an object identifier to its corresponding TypedPrincipal
        /// </summary>
        /// <param name="identifier">String identifier for an object, usually a guid or sid</param>
        /// <param name="objectDomain">The domain the object belongs too</param>
        /// <returns>A tuple containing success state as well as the resolved principal if successful</returns>
        Task<(bool Success, TypedPrincipal Principal)>
            ResolveIDAndType(string identifier, string objectDomain);

        /// <summary>
        /// Attempts to resolve a security identifier to its corresponding well known principal
        /// </summary>
        /// <param name="securityIdentifier"></param>
        /// <param name="objectDomain"></param>
        /// <returns>A tuple containing success state as well as the resolved principal if successful</returns>
        Task<(bool Success, TypedPrincipal WellKnownPrincipal)> GetWellKnownPrincipal(
            string securityIdentifier, string objectDomain);

        /// <summary>
        /// Attempts to resolve the domain name for a security identifier.
        /// </summary>
        /// <param name="sid">String security identifier for an object</param>
        /// <returns>A tuple containing success state as well as the resolved domain name if successful</returns>
        Task<(bool Success, string DomainName)> GetDomainNameFromSid(string sid);
        /// <summary>
        /// Attempts to resolve the sid for a domain given its name
        /// </summary>
        /// <param name="domainName">The domain name to resolve</param>
        /// <returns>A tuple containing success state as well as the resolved domain sid if successful</returns>
        Task<(bool Success, string DomainSid)> GetDomainSidFromDomainName(string domainName);
        /// <summary>
        /// Attempts to retrieve the Domain object for the specified domain
        /// </summary>
        /// <param name="domainName">The domain name to retrieve the Domain object for</param>
        /// <returns>True if the domain was found, false if not</returns>
        Task<(bool, System.DirectoryServices.ActiveDirectory.Domain)> GetDomain(string domainName);
        /// <summary>
        /// Attempts to retrieve the Domain object for the user's current domain
        /// </summary>
        /// <returns>True if the domain was found, false if not</returns>
        Task<(bool, System.DirectoryServices.ActiveDirectory.Domain)> GetDomain();

        Task<(bool Success, string ForestName)> GetForest(string domain);
        /// <summary>
        /// Attempts to resolve an account name to its corresponding typed principal
        /// </summary>
        /// <param name="name">The account name to resolve</param>
        /// <param name="domain">The domain to resolve the account in</param>
        /// <returns>A tuple containing success state as well as the resolved TypedPrincipal if successful</returns>
        Task<(bool Success, TypedPrincipal Principal)> ResolveAccountName(string name, string domain);
        /// <summary>
        /// Attempts to resolve a host to its corresponding security identifier in AD
        /// </summary>
        /// <param name="host">The hostname to resolve. Will accept an IP or a hostname</param>
        /// <param name="domain">The domain to lookup the account in</param>
        /// <returns>A tuple containing success state as well as the resolved computer sid if successful</returns>
        Task<(bool Success, string SecurityIdentifier)> ResolveHostToSid(string host, string domain);
        /// <summary>
        /// Attempts to look up possible matches for a user in the global catalog
        /// </summary>
        /// <param name="name">The name of the account to look up</param>
        /// <param name="domain">The domain to connect to a global catalog for</param>
        /// <returns>A tuple containing success state as well as all potential account matches in the global catalog</returns>
        Task<(bool Success, string[] Sids)> GetGlobalCatalogMatches(string name, string domain);
        /// <summary>
        /// Attempts to resolve a certificate template by a specific property
        /// </summary>
        /// <param name="propValue">The value of the property being matched</param>
        /// <param name="propName">The name of the property being matched</param>
        /// <param name="domainName">The domain to lookup the certificate template in</param>
        /// <returns>A tuple containing success state as well as the resolved certificate template if successful</returns>
        Task<(bool Success, TypedPrincipal Principal)> ResolveCertTemplateByProperty(string propValue, string propName, string domainName);
        /// <summary>
        /// Makes a new security descriptor object. This is a testing shim
        /// </summary>
        /// <returns>An ActiveDirectorySecurityDescriptor object</returns>
        ActiveDirectorySecurityDescriptor MakeSecurityDescriptor();

        /// <summary>
        /// Attempts to convert a local-to-computer well known principal
        /// </summary>
        /// <param name="sid">The security identifier to convert</param>
        /// <param name="computerDomainSid">The sid of the computer in the domain</param>
        /// <param name="computerDomain">The domain of the computer</param>
        /// <returns>A tuple containing success state as well as the resolved principal if successful</returns>
        Task<(bool Success, TypedPrincipal Principal)> ConvertLocalWellKnownPrincipal(SecurityIdentifier sid,
            string computerDomainSid, string computerDomain);

        /// <summary>
        /// Attempts to determine if a computer sid corresponds to a domain controller
        /// </summary>
        /// <param name="computerObjectId">The sid of the computer being tested</param>
        /// <param name="domainName">The domain to lookup the computer</param>
        /// <returns>True if the SID is a domain controller, false if not or if the object is not found</returns>
        Task<bool> IsDomainController(string computerObjectId, string domainName);
        /// <summary>
        /// Attempts to resolve a distinguished name to its corresponding principal
        /// </summary>
        /// <param name="distinguishedName">The distinguished name to resolve</param>
        /// <returns>A tuple containing success state as well as the resolved principal sid if successful</returns>
        Task<(bool Success, TypedPrincipal Principal)> ResolveDistinguishedName(string distinguishedName);
        void AddDomainController(string domainControllerSID);
        IAsyncEnumerable<OutputBase> GetWellKnownPrincipalOutput();
        Task<(bool Success, string DSHeuristics)> GetDSHueristics(string domain, string dn);
        /// <summary>
        /// Sets the ldap config for this utils instance. Will dispose if any existing ldap connections when set
        /// </summary>
        /// <param name="config">The new ldap config</param>
        void SetLdapConfig(LdapConfig config);
        /// <summary>
        /// Tests if a LDAP connection can be made successfully to a domain
        /// </summary>
        /// <param name="domain">The domain to test</param>
        /// <returns>A tuple containing success state as well as a message if unsuccessful</returns>
        Task<(bool Success, string Message)> TestLdapConnection(string domain);
        /// <summary>
        /// Attempts to get the distinguished name corresponding to a specific naming context for a domain
        /// </summary>
        /// <param name="domain">The domain to get the context for</param>
        /// <param name="context">The naming context being retrieved</param>
        /// <returns>A tuple containing success state as well as the resolved distinguished name if successful</returns>
        Task<(bool Success, string Path)> GetNamingContextPath(string domain, NamingContext context);

        /// <summary>
        /// Resets temporary caches in LDAPUtils
        /// </summary>
        void ResetUtils();
    }
}