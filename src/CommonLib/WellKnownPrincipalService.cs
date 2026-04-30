using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;
using Group = SharpHoundCommonLib.OutputTypes.Group;

namespace SharpHoundCommonLib;

/// <summary>
/// Handles all well-known principal resolution and output generation.
/// Extracted from LdapUtils to give WKP logic a single, focused home.
///
/// Dependencies are accepted as ILdapUtils so that Moq-based test overrides of
/// virtual methods (GetForest, GetDomainNameFromSid, etc.) continue to work.
/// </summary>
internal class WellKnownPrincipalService {
    // Tracks every well-known principal this session has resolved so we can emit
    // them as BloodHound output objects at the end of a run.
    // Static so state is shared across all LdapUtils instances (same as original).
    private static readonly ConcurrentDictionary<string, ResolvedWellKnownPrincipal> SeenWellKnownPrincipals = new();

    private readonly ILdapUtils _utils;
    private readonly DomainControllerRegistry _dcRegistry;
    private readonly ILogger _log;

    internal WellKnownPrincipalService(ILdapUtils utils, DomainControllerRegistry dcRegistry, ILogger log) {
        _utils = utils;
        _dcRegistry = dcRegistry;
        _log = log;
    }

    internal async Task<(bool Success, TypedPrincipal WellKnownPrincipal)> GetWellKnownPrincipal(
        string securityIdentifier, string objectDomain) {
        if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out var wellKnownPrincipal)) {
            return (false, null);
        }

        var (newIdentifier, newDomain) =
            await GetWellKnownPrincipalObjectIdentifier(securityIdentifier, objectDomain);

        wellKnownPrincipal.ObjectIdentifier = newIdentifier;
        SeenWellKnownPrincipals.TryAdd(wellKnownPrincipal.ObjectIdentifier, new ResolvedWellKnownPrincipal {
            DomainName = newDomain,
            WkpId = securityIdentifier
        });

        return (true, wellKnownPrincipal);
    }

    /// <summary>
    /// Converts a raw well-known SID into its domain- (or forest-) prefixed object identifier.
    /// Internal so PrincipalResolver can use it directly from ResolveAccountName.
    /// </summary>
    internal async Task<(string ObjectID, string Domain)> GetWellKnownPrincipalObjectIdentifier(
        string securityIdentifier, string domain) {
        if (!WellKnownPrincipal.GetWellKnownPrincipal(securityIdentifier, out _))
            return (securityIdentifier, string.Empty);

        if (!securityIdentifier.Equals("S-1-5-9", StringComparison.OrdinalIgnoreCase)) {
            var tempDomain = domain;
            if (_utils.GetDomain(tempDomain, out var domainObject) && domainObject.Name != null) {
                tempDomain = domainObject.Name;
            }

            return ($"{tempDomain}-{securityIdentifier}".ToUpper(), tempDomain);
        }

        if (await _utils.GetForest(domain) is (true, var forest)) {
            return ($"{forest}-{securityIdentifier}".ToUpper(), forest);
        }

        _log.LogWarning("Failed to get a forest name for domain {Domain}, unable to resolve enterprise DC sid",
            domain);
        return ($"UNKNOWN-{securityIdentifier}", "UNKNOWN");
    }

    internal async Task<(bool Success, TypedPrincipal Principal)> ConvertLocalWellKnownPrincipal(
        SecurityIdentifier sid, string computerDomainSid, string computerDomain) {
        if (!WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common)) return (false, null);

        // "Everyone" and "Authenticated Users" are mapped to the domain equivalent
        if (sid.Value is "S-1-1-0" or "S-1-5-11") {
            return await GetWellKnownPrincipal(sid.Value, computerDomain);
        }

        var principal = new TypedPrincipal {
            ObjectIdentifier = $"{computerDomainSid}-{sid.Rid()}",
            ObjectType = common.ObjectType switch {
                Label.User => Label.LocalUser,
                Label.Group => Label.LocalGroup,
                _ => common.ObjectType
            }
        };

        return (true, principal);
    }

    internal async IAsyncEnumerable<OutputBase> GetWellKnownPrincipalOutput() {
        foreach (var wkp in SeenWellKnownPrincipals) {
            WellKnownPrincipal.GetWellKnownPrincipal(wkp.Value.WkpId, out var principal);
            OutputBase output = principal.ObjectType switch {
                Label.User => new User(),
                Label.Computer => new Computer(),
                Label.Group => new Group(),
                Label.GPO => new GPO(),
                Label.Domain => new OutputTypes.Domain(),
                Label.OU => new OU(),
                Label.Container => new Container(),
                Label.Configuration => new Container(),
                _ => throw new ArgumentOutOfRangeException()
            };

            output.Properties.Add("name", $"{principal.ObjectIdentifier}@{wkp.Value.DomainName}".ToUpper());
            if (await _utils.GetDomainSidFromDomainName(wkp.Value.DomainName) is (true, var sid)) {
                output.Properties.Add("domainsid", sid);
            }

            output.Properties.Add("domain", wkp.Value.DomainName.ToUpper());
            output.ObjectIdentifier = wkp.Key;
            yield return output;
        }

        await foreach (var entdc in GetEnterpriseDCGroups()) {
            yield return entdc;
        }
    }

    private async IAsyncEnumerable<Group> GetEnterpriseDCGroups() {
        var grouped = new ConcurrentDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var forestSidToName = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domainSid in _dcRegistry.Values().GroupBy(x =>
                     new SecurityIdentifier(x).AccountDomainSid.Value)) {
            if (await _utils.GetDomainNameFromSid(domainSid.Key) is (true, var domainName) &&
                await _utils.GetForest(domainName) is (true, var forestName) &&
                await _utils.GetDomainSidFromDomainName(forestName) is (true, var forestDomainSid)) {
                forestSidToName.TryAdd(forestDomainSid, forestName);
                if (!grouped.ContainsKey(forestDomainSid)) {
                    grouped[forestDomainSid] = new();
                }

                foreach (var k in domainSid) {
                    grouped[forestDomainSid].Add(k);
                }
            }
        }

        foreach (var f in grouped) {
            if (!forestSidToName.TryGetValue(f.Key, out var forestName)) {
                _log.LogWarning("Could not get a mapped value for well known principal {Key}", f.Key);
                continue;
            }

            var group = new Group { ObjectIdentifier = $"{forestName}-S-1-5-9" };
            group.Properties.Add("name", $"ENTERPRISE DOMAIN CONTROLLERS@{forestName}".ToUpper());
            group.Properties.Add("domainsid", f.Key);
            group.Properties.Add("domain", forestName);
            group.Members = f.Value.Select(x => new TypedPrincipal(x, Label.Computer)).ToArray();
            yield return group;
        }
    }

    private class ResolvedWellKnownPrincipal {
        public string DomainName { get; set; }
        public string WkpId { get; set; }
    }
}
