using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.DirectoryObjects;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class ContainerProcessor
    {
        private readonly ILogger _log;
        private readonly ILdapUtils _utils;

        public ContainerProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("ContainerProc");
        }

        private static bool IsDistinguishedNameFiltered(string distinguishedName)
        {
            var dn = distinguishedName.ToUpper();
            if (dn.Contains("CN=PROGRAM DATA,DC=")) return true;

            if (dn.Contains("CN=SYSTEM,DC=")) return true;

            return false;
        }

        /// <summary>
        /// Helper function to pass commonlib types to GetContainingObject
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal principal)> GetContainingObject(IDirectoryObject entry)
        {
            if (entry.TryGetDistinguishedName(out var dn)) {
                _log.LogTrace("Reading containing object for {DN}", dn);
                return await GetContainingObject(dn);
            }

            return (false, default);
        }

        /// <summary>
        /// Uses the distinguishedname of an object to get its containing object by stripping the first part and using the remainder to find the container object
        /// Saves lots of LDAP calls compared to enumerating container info directly
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal Principal)> GetContainingObject(string distinguishedName)
        {
            var containerDn = Helpers.RemoveDistinguishedNamePrefix(distinguishedName);

            return await _utils.ResolveDistinguishedName(containerDn);
        }

        /// <summary>
        ///     Helper function using commonlib types to pass to GetContainerChildObjects
        /// </summary>
        /// <param name="result"></param>
        /// <param name="entry"></param>
        /// <returns></returns>
        public IAsyncEnumerable<TypedPrincipal> GetContainerChildObjects(ResolvedSearchResult result,
            IDirectoryObject entry)
        {
            var name = result.DisplayName;
            if (entry.TryGetDistinguishedName(out var dn)) {
                return GetContainerChildObjects(dn, name);    
            }
            
            return AsyncEnumerable.Empty<TypedPrincipal>();
        }

        /// <summary>
        ///     Finds all immediate child objects of a container.
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="containerName"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<TypedPrincipal> GetContainerChildObjects(string distinguishedName, string containerName = "")
        {
            var filter = new LdapFilter().AddComputers().AddUsers().AddGroups().AddOUs().AddContainers()
                .AddBuiltinDomains().AddSitesContainer();
            filter.AddCertificateAuthorities().AddCertificateTemplates().AddEnterpriseCertificationAuthorities();
            await foreach (var childEntryResult in _utils.Query(new LdapQueryParameters {
                               DomainName = Helpers.DistinguishedNameToDomain(distinguishedName),
                               SearchScope = SearchScope.OneLevel,
                               Attributes = CommonProperties.ObjectID,
                               LDAPFilter = filter.GetFilter(),
                               SearchBase = distinguishedName
                           })) {
                if (!childEntryResult.IsSuccess) {
                    _log.LogWarning("Error while getting container child objects for {DistinguishedName}: {Reason}", distinguishedName, childEntryResult.Error);
                    yield break;
                }

                var childEntry = childEntryResult.Value;
                if (!childEntry.TryGetDistinguishedName(out var dn) || IsDistinguishedNameFiltered(dn)) {
                    _log.LogTrace("Skipping filtered child {Child} for {Container}", dn, containerName);
                    continue;
                }

                if (!childEntry.GetObjectIdentifier(out var id)) {
                    _log.LogTrace("Got null ID for {ChildDN} under {Container}", dn,
                        containerName);
                    continue;
                }

                var res = await _utils.ResolveIDAndType(id, Helpers.DistinguishedNameToDomain(dn));
                if (res.Success) {
                    yield return res.Principal;
                }
            }
        }

        public IAsyncEnumerable<GPLink> ReadContainerGPLinks(ResolvedSearchResult result, IDirectoryObject entry)
        {
            return Helpers.ReadGPLinks(entry, _utils);
        }

        /// <summary>
        ///     Reads the "gplink" property from a SearchResult and converts the links into the acceptable SharpHound format
        /// </summary>
        /// <param name="gpLink"></param>
        /// <returns></returns>
        public IAsyncEnumerable<GPLink> ReadContainerGPLinks(string gpLink)
        {
            return Helpers.ReadGPLinks(gpLink, _utils);
        }

        /// <summary>
        ///     Checks if a container blocks privilege inheritance
        /// </summary>
        /// <param name="gpOptions"></param>
        /// <returns></returns>
        public static bool ReadBlocksInheritance(string gpOptions)
        {
            return gpOptions is "1";
        }
    }
}
