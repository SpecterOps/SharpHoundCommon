using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib.Processors
{
    public class SiteProcessor
    {
        private readonly ILogger _log;
        private readonly ILdapUtils _utils;

        public SiteProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("SiteProc");
        }


        /// <summary>
        /// Helper function to pass commonlib types to GetContainingSiteForServer
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal principal)> GetContainingSiteForServer(IDirectoryObject entry)
        {
            if (entry.TryGetDistinguishedName(out var dn))
            {
                _log.LogTrace("Reading containing site for server {DN}", dn);
                return await GetContainingSiteForServer(dn);
            }

            return (false, default);
        }

        /// <summary>
        /// Helper function to pass commonlib types to GetContainingSiteForSubnet
        /// </summary>
        /// <param name="entry"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal principal)> GetContainingSiteForSubnet(Dictionary<string, object> subnetProperties)
        {
            if (subnetProperties.TryGetValue("siteObject", out var siteObject))
            {
                if (siteObject == null)
                    return (false, default);

                var siteObjectDn = siteObject.ToString();
                if (string.IsNullOrWhiteSpace(siteObjectDn))
                    return (false, default);

                return await GetContainingSiteForSubnet(siteObjectDn);
            }
            return (false, default);
        }

        public async Task<(bool Success, TypedPrincipal principal)> GetReferencedComputerForServer(IDirectoryObject entry)
        {
            if (entry.TryGetProperty(LDAPProperties.ServerReference, out var serverReference))
            {
                return await GetReferencedComputerForServer(serverReference);
            }

            return (false, default);
        }

        public async Task<(bool Success, TypedPrincipal principal)> GetReferencedComputerForServer(Dictionary<string, object> serverProperties)
        {
            if (!serverProperties.TryGetValue(LDAPProperties.ServerReference, out var serverReference) ||
                serverReference == null)
            {
                return (false, default);
            }

            return await GetReferencedComputerForServer(serverReference.ToString());
        }

        /// <summary>
        /// Uses the distinguishedname of a site server object to get its containing site by stripping the two first parts and using the remainder to find the container object
        /// Saves lots of LDAP calls compared to enumerating container info directly
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal Principal)> GetContainingSiteForServer(string distinguishedName)
        {
            var servercontainerdn = Helpers.RemoveDistinguishedNamePrefix(distinguishedName);
            var sitedn = Helpers.RemoveDistinguishedNamePrefix(servercontainerdn);
            return await _utils.ResolveDistinguishedName(sitedn);
        }

        /// <summary>
        /// Uses the siteObject of a subnet to get its containing site
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <returns></returns>
        public async Task<(bool Success, TypedPrincipal Principal)> GetContainingSiteForSubnet(string siteObject)
        {
            return await _utils.ResolveDistinguishedName(siteObject);
        }

        public async Task<(bool Success, TypedPrincipal Principal)> GetReferencedComputerForServer(string serverReference)
        {
            if (string.IsNullOrWhiteSpace(serverReference))
            {
                return (false, default);
            }

            var resolved = await _utils.ResolveDistinguishedName(serverReference);
            if (!resolved.Success || resolved.Principal == null || resolved.Principal.ObjectType != Label.Computer)
            {
                return (false, default);
            }

            return resolved;
        }

        public IAsyncEnumerable<GPLink> ReadSiteGPLinks(ResolvedSearchResult result, IDirectoryObject entry)
        {
            if (entry.TryGetProperty(LDAPProperties.GPLink, out var links))
            {
                return ReadSiteGPLinks(links);
            }

            return AsyncEnumerable.Empty<GPLink>();
        }

        /// <summary>
        ///     Reads the "gplink" property from a SearchResult and converts the links into the acceptable SharpHound format
        /// </summary>
        /// <param name="gpLink"></param>
        /// <returns></returns>
        public async IAsyncEnumerable<GPLink> ReadSiteGPLinks(string gpLink)
        {
            if (gpLink == null)
                yield break;

            foreach (var link in Helpers.SplitGPLinkProperty(gpLink))
            {
                var enforced = link.Status.Equals("2");

                var res = await _utils.ResolveDistinguishedName(link.DistinguishedName);

                if (res.Success)
                {
                    yield return new GPLink
                    {
                        GUID = res.Principal.ObjectIdentifier,
                        IsEnforced = enforced
                    };
                }
            }
        }
    }
}
