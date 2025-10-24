using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using System.DirectoryServices.Protocols;
using System.Drawing.Printing;

namespace SharpHoundCommonLib.Processors
{
    public class GPOUserRightsAssignmentProcessor
    {
        // Regex to parse key=value lines in the INI file
        private static readonly Regex KeyRegex = new(@"(.+?)\s*=(.*)", RegexOptions.Compiled);

        // Regex to extract the [Privilege Rights] section
        private static readonly Regex PrivilegeRightsRegex =
            new(@"\[Privilege Rights\](.*)(?:\[|$)", RegexOptions.Compiled | RegexOptions.Singleline);

        // Cache to store processed GPO privilege actions
        private static readonly ConcurrentDictionary<string, List<PrivilegeAction>> GpoPrivilegeCache = new();

        private readonly ILogger _log;
        private readonly ILdapUtils _utils;

        public GPOUserRightsAssignmentProcessor(ILdapUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("GPOUserRightsProc");
        }

        public Task<ResultingGPOUserRights> ReadGPOUserRights(IDirectoryObject entry)
        {
            if (entry.TryGetProperty(LDAPProperties.GPLink, out var links) &&
                entry.TryGetDistinguishedName(out var dn))
            {
                return ReadGPOUserRights(links, dn);
            }

            return Task.FromResult(new ResultingGPOUserRights());
        }

        public async Task<ResultingGPOUserRights> ReadGPOUserRights(string gpLink, string distinguishedName)
        {
            var ret = new ResultingGPOUserRights();

            // If the gplink property is null, we don't need to process anything
            if (gpLink == null)
                return ret;

            string domain;
            // If our dn is null, use our default domain
            if (string.IsNullOrEmpty(distinguishedName))
            {
                if (!_utils.GetDomain(out var domainResult))
                {
                    return ret;
                }
                domain = domainResult.Name;
            }
            else
            {
                domain = Helpers.DistinguishedNameToDomain(distinguishedName);
            }

            // First check if this OU has computers
            var affectedComputers = new List<TypedPrincipal>();
            await foreach (var result in _utils.Query(new LdapQueryParameters()
            {
                LDAPFilter = new LdapFilter().AddComputersNoMSAs().GetFilter(),
                Attributes = CommonProperties.ObjectSID,
                SearchBase = distinguishedName,
                DomainName = domain
            }))
            {
                if (!result.IsSuccess)
                {
                    break;
                }

                var entry = result.Value;
                if (!entry.TryGetSecurityIdentifier(out var sid))
                {
                    continue;
                }

                affectedComputers.Add(new TypedPrincipal(sid, Label.Computer));
            }

            // If there's no computers then we don't care about this OU
            if (affectedComputers.Count == 0)
                return ret;

            var enforced = new List<string>();
            var unenforced = new List<string>();

            // Split our link property up and remove disabled links
            foreach (var link in Helpers.SplitGPLinkProperty(gpLink))
                switch (link.Status)
                {
                    case "0":
                        unenforced.Add(link.DistinguishedName);
                        break;
                    case "2":
                        enforced.Add(link.DistinguishedName);
                        break;
                }

            // Set up our links in the correct order
            var orderedLinks = new List<string>();
            orderedLinks.AddRange(unenforced);
            orderedLinks.AddRange(enforced);

            // Dictionary to store principals for each privilege
            var privilegeData = new Dictionary<string, List<TypedPrincipal>>();

            foreach (var linkDn in orderedLinks)
            {
                if (!GpoPrivilegeCache.TryGetValue(linkDn.ToLower(), out var actions))
                {
                    actions = new List<PrivilegeAction>();

                    var gpoDomain = Helpers.DistinguishedNameToDomain(linkDn);
                    var result = await _utils.Query(new LdapQueryParameters()
                    {
                        LDAPFilter = new LdapFilter().AddAllObjects().GetFilter(),
                        SearchScope = SearchScope.Base,
                        Attributes = new[] { LDAPProperties.GPCFileSYSPath, LDAPProperties.Flags },
                        SearchBase = linkDn,
                        DomainName = gpoDomain
                    }).DefaultIfEmpty(LdapResult<IDirectoryObject>.Fail()).FirstOrDefaultAsync();

                    if (!result.IsSuccess)
                    {
                        continue;
                    }

                    if (!result.Value.TryGetProperty(LDAPProperties.GPCFileSYSPath, out var filePath) ||
                        // Filter out GPOs that are disabled or the computer configuration is disabled
                        (result.Value.TryGetProperty(LDAPProperties.Flags, out var flags) && flags is "2" or "3"))
                    {
                        GpoPrivilegeCache.TryAdd(linkDn.ToLower(), actions);
                        continue;
                    }

                    // Process the GPO template file for privilege rights
                    await foreach (var item in ProcessGPOTemplateFilePrivileges(filePath, gpoDomain))
                    {
                        actions.Add(item);
                    }

                    GpoPrivilegeCache.TryAdd(linkDn.ToLower(), actions);
                }

                // If there are no actions, move to next GPO
                if (actions.Count == 0)
                    continue;

                // Process each privilege action
                // Later GPOs override earlier ones (last write wins)
                foreach (var action in actions)
                {
                    if (!privilegeData.ContainsKey(action.PrivilegeName))
                    {
                        privilegeData[action.PrivilegeName] = new List<TypedPrincipal>();
                    }

                    // Replace the entire list (GPO privileges are absolute, not additive)
                    privilegeData[action.PrivilegeName] = action.Principals.ToList();
                }
            }

            ret.AffectedComputers = affectedComputers.ToArray();

            // Convert to the final format
            ret.UserRightAssignments = privilegeData.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.Distinct().ToArray()
            );

            return ret;
        }

        /// <summary>
        ///     Parses a GPO GptTmpl.inf file and extracts privilege rights assignments
        /// </summary>
        /// <param name="basePath">Base path to the GPO</param>
        /// <param name="gpoDomain">Domain of the GPO</param>
        /// <returns>Enumerable of privilege actions</returns>
        internal async IAsyncEnumerable<PrivilegeAction> ProcessGPOTemplateFilePrivileges(string basePath, string gpoDomain)
        {
            var templatePath = Path.Combine(basePath, "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf");

            if (!File.Exists(templatePath))
                yield break;

            FileStream fs;
            try
            {
                fs = new FileStream(templatePath, FileMode.Open, FileAccess.Read);
            }
            catch (Exception e)
            {
                _log.LogWarning(e, "Failed to open template file {Path}", templatePath);
                yield break;
            }

            using var reader = new StreamReader(fs);
            var content = await reader.ReadToEndAsync();
            var privilegeMatch = PrivilegeRightsRegex.Match(content);

            if (!privilegeMatch.Success)
                yield break;

            // Extract the [Privilege Rights] section
            var privilegeText = privilegeMatch.Groups[1].Value.Trim();
            var privilegeLines = Regex.Split(privilegeText, @"\r\n|\r|\n");

            foreach (var line in privilegeLines)
            {
                var keyMatch = KeyRegex.Match(line);

                if (!keyMatch.Success)
                    continue;

                var privilegeName = keyMatch.Groups[1].Value.Trim();
                var membersText = keyMatch.Groups[2].Value.Trim();

                // Skip empty privilege assignments
                if (string.IsNullOrWhiteSpace(membersText))
                    continue;

                var principals = new List<TypedPrincipal>();

                // Parse each member (comma-separated SIDs with * prefix)
                foreach (var member in membersText.Split(','))
                {
                    var cleanMember = member.Trim().TrimStart('*');

                    if (string.IsNullOrWhiteSpace(cleanMember))
                        continue;

                    // Resolve the SID to a typed principal
                    if (await GetSid(cleanMember, gpoDomain) is (true, var principal))
                    {
                        principals.Add(principal);
                    }
                }

                // Only yield if we successfully resolved at least one principal
                if (principals.Count > 0)
                {
                    yield return new PrivilegeAction
                    {
                        PrivilegeName = privilegeName,
                        Principals = principals.ToArray()
                    };
                }
            }
        }

        /// <summary>
        ///     Resolves a SID or account name to a TypedPrincipal
        /// </summary>
        private async Task<(bool Success, TypedPrincipal Principal)> GetSid(string account, string domainName)
        {
            if (!account.StartsWith("S-1-", StringComparison.CurrentCulture))
            {
                string user;
                string domain;
                if (account.Contains('\\'))
                {
                    // The account is in the format DOMAIN\username
                    var split = account.Split('\\');
                    domain = split[0];
                    user = split[1];
                }
                else
                {
                    // The account is just a username, so try with the current domain
                    domain = domainName;
                    user = account;
                }

                user = user.ToUpper();

                // Try to resolve as a user object first
                var (success, res) = await _utils.ResolveAccountName(user, domain);
                if (success)
                    return (true, res);

                // Try as a computer account
                return await _utils.ResolveAccountName($"{user}$", domain);
            }

            // The element is just a SID, so resolve it
            return await _utils.ResolveIDAndType(account, domainName);
        }

        /// <summary>
        ///     Represents a privilege assignment action from a GPO
        /// </summary>
        internal class PrivilegeAction
        {
            internal string PrivilegeName { get; set; }
            internal TypedPrincipal[] Principals { get; set; }

            public override string ToString()
            {
                return $"{nameof(PrivilegeName)}: {PrivilegeName}, Principals: {Principals?.Length ?? 0}";
            }
        }
    }
}