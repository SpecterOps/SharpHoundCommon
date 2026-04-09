using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.Exceptions;
using SharpHoundCommonLib.LDAPQueries;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC.NetAPINative;
using Domain = System.DirectoryServices.ActiveDirectory.Domain;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;
using SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks;

namespace SharpHoundCommonLib
{
    public class LDAPUtils : ILDAPUtils
    {
        private const string NullCacheKey = "UNIQUENULL";

        // The following byte stream contains the necessary message to request a NetBios name from a machine
        // http://web.archive.org/web/20100409111218/http://msdn.microsoft.com/en-us/library/system.net.sockets.socket.aspx
        private static readonly byte[] NameRequest =
        {
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        };


        private static readonly ConcurrentDictionary<string, ResolvedWellKnownPrincipal>
            SeenWellKnownPrincipals = new();

        private static readonly ConcurrentDictionary<string, byte> DomainControllers = new();
        private static readonly ConcurrentDictionary<string, DomainInfo> CachedDomainInfo = new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, Domain> _domainCache = new();
        private static readonly TimeSpan MinBackoffDelay = TimeSpan.FromSeconds(2);
        private static readonly TimeSpan MaxBackoffDelay = TimeSpan.FromSeconds(20);
        private const int BackoffDelayMultiplier = 2;
        private const int MaxRetries = 3;
        
        private readonly ConcurrentDictionary<string, string> _hostResolutionMap = new();
        private readonly ConcurrentDictionary<LDAPConnectionCacheKey, LdapConnectionWrapper> _ldapConnections = new();
        private readonly ConcurrentDictionary<string, int> _ldapRangeSizeCache = new();
        private readonly ILogger _log;
        private readonly NativeMethods _nativeMethods;
        private readonly ConcurrentDictionary<string, string> _netbiosCache = new();
        private readonly PortScanner _portScanner;
        private LDAPConfig _ldapConfig = new();
        private readonly ManualResetEvent _connectionResetEvent = new(false);
        private readonly object _lockObj = new();


        /// <summary>
        ///     Creates a new instance of LDAP Utils with defaults
        /// </summary>
        public LDAPUtils()
        {
            _nativeMethods = new NativeMethods();
            _portScanner = new PortScanner();
            _log = Logging.LogProvider.CreateLogger("LDAPUtils");
        }

        /// <summary>
        ///     Creates a new instance of LDAP utils and allows overriding implementations
        /// </summary>
        /// <param name="nativeMethods"></param>
        /// <param name="scanner"></param>
        /// <param name="log"></param>
        public LDAPUtils(NativeMethods nativeMethods = null, PortScanner scanner = null, ILogger log = null)
        {
            _nativeMethods = nativeMethods ?? new NativeMethods();
            _portScanner = scanner ?? new PortScanner();
            _log = log ?? Logging.LogProvider.CreateLogger("LDAPUtils");
        }

        /// <summary>
        ///     Sets the configuration for LDAP queries
        /// </summary>
        /// <param name="config"></param>
        /// <exception cref="Exception"></exception>
        public void SetLDAPConfig(LDAPConfig config)
        {
            _ldapConfig = config ?? throw new Exception("LDAP Configuration can not be null");
            //Close out any existing LDAP connections to request a new incoming config
            foreach (var kv in _ldapConnections)
            {
                kv.Value.Connection.Dispose();
            }

            _ldapConnections.Clear();
        }

        /// <summary>
        ///     Turns a sid into a well known principal ID.
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <param name="commonPrincipal"></param>
        /// <returns>True if a well known principal was identified, false if not</returns>
        public bool GetWellKnownPrincipal(string sid, string domain, out TypedPrincipal commonPrincipal)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid, out commonPrincipal)) return false;
            var tempDomain = domain ?? GetDomain()?.Name ?? "UNKNOWN";
            commonPrincipal.ObjectIdentifier = ConvertWellKnownPrincipal(sid, tempDomain);
            SeenWellKnownPrincipals.TryAdd(commonPrincipal.ObjectIdentifier, new ResolvedWellKnownPrincipal
            {
                DomainName = domain,
                WkpId = sid
            });
            return true;
        }
        
        public bool ConvertLocalWellKnownPrincipal(SecurityIdentifier sid, string computerDomainSid,
            string computerDomain, out TypedPrincipal principal)
        {
            if (WellKnownPrincipal.GetWellKnownPrincipal(sid.Value, out var common))
            {
                //The everyone and auth users principals are special and will be converted to the domain equivalent
                if (sid.Value is "S-1-1-0" or "S-1-5-11")
                {
                    GetWellKnownPrincipal(sid.Value, computerDomain, out principal);
                    return true;
                }

                //Use the computer object id + the RID of the sid we looked up to create our new principal
                principal = new TypedPrincipal
                {
                    ObjectIdentifier = $"{computerDomainSid}-{sid.Rid()}",
                    ObjectType = common.ObjectType switch
                    {
                        Label.User => Label.LocalUser,
                        Label.Group => Label.LocalGroup,
                        _ => common.ObjectType
                    }
                };

                return true;
            }

            principal = null;
            return false;
        }

        /// <summary>
        ///     Adds a SID to an internal list of domain controllers
        /// </summary>
        /// <param name="domainControllerSID"></param>
        public void AddDomainController(string domainControllerSID)
        {
            DomainControllers.TryAdd(domainControllerSID, new byte());
        }

        /// <summary>
        ///     Gets output objects for currently observed well known principals
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public IEnumerable<OutputBase> GetWellKnownPrincipalOutput(string domain)
        {
            foreach (var wkp in SeenWellKnownPrincipals)
            {
                WellKnownPrincipal.GetWellKnownPrincipal(wkp.Value.WkpId, out var principal);
                OutputBase output = principal.ObjectType switch
                {
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
                var domainSid = GetSidFromDomainName(wkp.Value.DomainName);
                output.Properties.Add("domainsid", domainSid);
                output.Properties.Add("domain", wkp.Value.DomainName.ToUpper());
                output.ObjectIdentifier = wkp.Key;
                yield return output;
            }

            var entdc = GetBaseEnterpriseDC(domain);
            entdc.Members = DomainControllers.Select(x => new TypedPrincipal(x.Key, Label.Computer)).ToArray();
            yield return entdc;
        }

        /// <summary>
        ///     Converts a
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public string ConvertWellKnownPrincipal(string sid, string domain)
        {
            if (!WellKnownPrincipal.GetWellKnownPrincipal(sid, out _)) return sid;

            if (sid != "S-1-5-9") return $"{domain}-{sid}".ToUpper();

            var forest = GetForest(domain)?.Name;
            if (forest == null) _log.LogWarning("Error getting forest, ENTDC sid is likely incorrect");
            return $"{forest ?? "UNKNOWN"}-{sid}".ToUpper();
        }

        /// <summary>
        ///     Queries the global catalog to get potential SID matches for a username in the forest
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public string[] GetUserGlobalCatalogMatches(string name)
        {
            var tempName = name.ToLower();
            if (Cache.GetGCCache(tempName, out var sids))
                return sids;

            var query = new LDAPFilter().AddUsers($"samaccountname={tempName}").GetFilter();
            var results = QueryLDAP(query, SearchScope.Subtree, new[] { "objectsid" }, globalCatalog: true)
                .Select(x => x.GetSid()).Where(x => x != null).ToArray();
            Cache.AddGCCache(tempName, results);
            return results;
        }

        /// <summary>
        ///     Uses an LDAP lookup to attempt to find the Label for a given SID
        ///     Will also convert to a well known principal ID if needed
        /// </summary>
        /// <param name="id"></param>
        /// <param name="fallbackDomain"></param>
        /// <returns></returns>
        public TypedPrincipal ResolveIDAndType(string id, string fallbackDomain)
        {
            //This is a duplicated SID object which is weird and makes things unhappy. Throw it out
            if (id.Contains("0ACNF"))
                return null;

            if (GetWellKnownPrincipal(id, fallbackDomain, out var principal))
                return principal;

            var type = id.StartsWith("S-") ? LookupSidType(id, fallbackDomain) : LookupGuidType(id, fallbackDomain);
            return new TypedPrincipal(id, type);
        }

        public TypedPrincipal ResolveCertTemplateByProperty(string propValue, string propertyName, string containerDN,
            string domainName)
        {
            var filter = new LDAPFilter().AddCertificateTemplates().AddFilter(propertyName + "=" + propValue, true);
            var res = QueryLDAP(filter.GetFilter(), SearchScope.OneLevel,
                CommonProperties.TypeResolutionProps, adsPath: containerDN, domainName: domainName);

            if (res == null)
            {
                _log.LogWarning(
                    "Could not find certificate template with '{propertyName}:{propValue}' under {containerDN}; null result",
                    propertyName, propValue, containerDN);
                return null;
            }

            List<ISearchResultEntry> resList = new List<ISearchResultEntry>(res);
            if (resList.Count == 0)
            {
                _log.LogWarning(
                    "Could not find certificate template with '{propertyName}:{propValue}' under {containerDN}; empty list",
                    propertyName, propValue, containerDN);
                return null;
            }

            if (resList.Count > 1)
            {
                _log.LogWarning(
                    "Found more than one certificate template with '{propertyName}:{propValue}' under {containerDN}",
                    propertyName, propValue, containerDN);
                return null;
            }

            ISearchResultEntry searchResultEntry = resList.FirstOrDefault();
            return new TypedPrincipal(searchResultEntry.GetGuid(), Label.CertTemplate);
        }

        /// <summary>
        ///     Attempts to lookup the Label for a sid
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public Label LookupSidType(string sid, string domain)
        {
            if (Cache.GetIDType(sid, out var type))
                return type;

            var rDomain = GetDomainNameFromSid(sid) ?? domain;

            var result =
                QueryLDAP(CommonFilters.SpecificSID(sid), SearchScope.Subtree, CommonProperties.TypeResolutionProps,
                        rDomain)
                    .DefaultIfEmpty(null).FirstOrDefault();

            type = result?.GetLabel() ?? Label.Base;
            Cache.AddType(sid, type);
            return type;
        }

        /// <summary>
        ///     Attempts to lookup the Label for a GUID
        /// </summary>
        /// <param name="guid"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public Label LookupGuidType(string guid, string domain)
        {
            if (Cache.GetIDType(guid, out var type))
                return type;

            var hex = Helpers.ConvertGuidToHexGuid(guid);
            if (hex == null)
                return Label.Base;

            var result =
                QueryLDAP($"(objectguid={hex})", SearchScope.Subtree, CommonProperties.TypeResolutionProps, domain)
                    .DefaultIfEmpty(null).FirstOrDefault();

            type = result?.GetLabel() ?? Label.Base;
            Cache.AddType(guid, type);
            return type;
        }

        /// <summary>
        ///     Attempts to find the domain associated with a SID
        /// </summary>
        /// <param name="sid"></param>
        /// <returns></returns>
        public string GetDomainNameFromSid(string sid)
        {
            try
            {
                var parsedSid = new SecurityIdentifier(sid);
                var domainSid = parsedSid.AccountDomainSid?.Value.ToUpper();
                if (domainSid == null)
                    return null;

                _log.LogDebug("Resolving sid {DomainSid}", domainSid);

                if (Cache.GetDomainSidMapping(domainSid, out var domain))
                    return domain;

                _log.LogDebug("No cache hit for {DomainSid}", domainSid);
                domain = GetDomainNameFromSidLdap(domainSid);
                _log.LogDebug("Resolved to {Domain}", domain);

                //Cache both to and from so we can use this later
                if (domain != null)
                {
                    Cache.AddDomainSidMapping(domainSid, domain);
                    Cache.AddDomainSidMapping(domain, domainSid);
                }

                return domain;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        ///     Attempts to get the SID associated with a domain name
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public string GetSidFromDomainName(string domainName)
        {
            var tempDomainName = NormalizeDomainName(domainName);
            if (tempDomainName == null)
                return null;
            if (Cache.GetDomainSidMapping(tempDomainName, out var sid)) return sid;

            var domainObj = GetDomain(tempDomainName);

            if (domainObj != null)
                sid = domainObj.GetDirectoryEntry().GetSid();
            else
                sid = null;

            if (sid != null)
            {
                Cache.AddDomainSidMapping(sid, tempDomainName);
                Cache.AddDomainSidMapping(tempDomainName, sid);
                if (tempDomainName != domainName)
                {
                    Cache.AddDomainSidMapping(domainName, sid);
                }
            }

            return sid;
        }

        // Saving this code for an eventual async implementation
        // public async IAsyncEnumerable<string> DoRangedRetrievalAsync(string distinguishedName, string attributeName)
        // {
        //     var domainName = Helpers.DistinguishedNameToDomain(distinguishedName);
        //     LdapConnection conn;
        //     try
        //     {
        //         conn = await CreateLDAPConnection(domainName, authType: _ldapConfig.AuthType);
        //     }
        //     catch
        //     {
        //         yield break;
        //     }
        //
        //     if (conn == null)
        //         yield break;
        //
        //     var index = 0;
        //     var step = 0;
        //     var currentRange = $"{attributeName};range={index}-*";
        //     var complete = false;
        //     
        //     var searchRequest = CreateSearchRequest($"{attributeName}=*", SearchScope.Base, new[] {currentRange},
        //         domainName, distinguishedName);
        //
        //     var backoffDelay = MinBackoffDelay;
        //     var retryCount = 0;
        //
        //     while (true)
        //     {
        //         DirectoryResponse searchResult;
        //         try
        //         {
        //             searchResult = await Task.Factory.FromAsync(conn.BeginSendRequest, conn.EndSendRequest,
        //                 searchRequest,
        //                 PartialResultProcessing.NoPartialResultSupport, null);
        //         }
        //         catch (LdapException le) when (le.ErrorCode == 51 && retryCount < MaxRetries)
        //         {
        //             //Allow three retries with a backoff on each one if we get a "Server is Busy" error
        //             retryCount++;
        //             await Task.Delay(backoffDelay);
        //             backoffDelay = TimeSpan.FromSeconds(Math.Min(
        //                 backoffDelay.TotalSeconds * BackoffDelayMultiplier.TotalSeconds, MaxBackoffDelay.TotalSeconds));
        //             continue;
        //         }
        //         catch (Exception e)
        //         {
        //             _log.LogWarning(e,"Caught exception during ranged retrieval for {DN}", distinguishedName);
        //             yield break;
        //         }
        //         
        //         if (searchResult is SearchResponse response && response.Entries.Count == 1)
        //         {
        //             var entry = response.Entries[0];
        //             var attributeNames = entry?.Attributes?.AttributeNames;
        //             if (attributeNames != null)
        //             {
        //                 foreach (string attr in attributeNames)
        //                 {
        //                     //Set our current range to the name of the attribute, which will tell us how far we are in "paging"
        //                     currentRange = attr;
        //                     //Check if the string has the * character in it. If it does, we've reached the end of this search 
        //                     complete = currentRange.IndexOf("*", 0, StringComparison.Ordinal) > 0;
        //                     //Set our step to the number of attributes that came back.
        //                     step = entry.Attributes[currentRange].Count;
        //                 }
        //             }
        //
        //
        //             foreach (string val in entry.Attributes[currentRange].GetValues(typeof(string)))
        //             {
        //                 yield return val;
        //                 index++;
        //             }
        //         
        //             if (complete) yield break;
        //
        //             currentRange = $"{attributeName};range={index}-{index + step}";
        //             searchRequest.Attributes.Clear();
        //             searchRequest.Attributes.Add(currentRange);
        //         }
        //         else
        //         {
        //             yield break;
        //         }
        //     }
        // }

        /// <summary>
        ///     Performs Attribute Ranged Retrieval
        ///     https://docs.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval
        ///     The function self-determines the range and internally handles the maximum step allowed by the server
        /// </summary>
        /// <param name="distinguishedName"></param>
        /// <param name="attributeName"></param>
        /// <returns></returns>
        public IEnumerable<string> DoRangedRetrieval(string distinguishedName, string attributeName)
        {
            var domainName = Helpers.DistinguishedNameToDomain(distinguishedName);
            var task = Task.Run(() => CreateLDAPConnectionWrapper(domainName, authType: _ldapConfig.AuthType));

            LdapConnectionWrapper connWrapper;

            try
            {
                connWrapper = task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch
            {
                yield break;
            }

            if (connWrapper.Connection == null)
                yield break;

            var conn = connWrapper.Connection;

            var index = 0;
            var step = 0;
            var baseString = $"{attributeName}";
            //Example search string: member;range=0-1000
            var currentRange = $"{baseString};range={index}-*";
            var complete = false;

            var searchRequest = CreateSearchRequest($"{attributeName}=*", SearchScope.Base, new[] { currentRange },
                connWrapper.DomainInfo, distinguishedName);

            if (searchRequest == null)
                yield break;

            var backoffDelay = MinBackoffDelay;
            var retryCount = 0;

            while (true)
            {
                SearchResponse response;
                try
                {
                    response = (SearchResponse)conn.SendRequest(searchRequest);
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.Busy && retryCount < MaxRetries)
                {
                    //Allow three retries with a backoff on each one if we get a "Server is Busy" error
                    retryCount++;
                    Thread.Sleep(backoffDelay);
                    backoffDelay = GetNextBackoff(retryCount);
                    continue;
                }
                catch (Exception e)
                {
                    _log.LogError(e, "Error doing ranged retrieval for {Attribute} on {Dn}", attributeName,
                        distinguishedName);
                    yield break;
                }

                //If we ever get more than one response from here, something is horribly wrong
                if (response?.Entries.Count == 1)
                {
                    var entry = response.Entries[0];
                    //Process the attribute we get back to determine a few things
                    foreach (string attr in entry.Attributes.AttributeNames)
                    {
                        //Set our current range to the name of the attribute, which will tell us how far we are in "paging"
                        currentRange = attr;
                        //Check if the string has the * character in it. If it does, we've reached the end of this search 
                        complete = currentRange.IndexOf("*", 0, StringComparison.Ordinal) > 0;
                        //Set our step to the number of attributes that came back.
                        step = entry.Attributes[currentRange].Count;
                    }

                    foreach (string val in entry.Attributes[currentRange].GetValues(typeof(string)))
                    {
                        yield return val;
                        index++;
                    }

                    if (complete) yield break;

                    currentRange = $"{baseString};range={index}-{index + step}";
                    searchRequest.Attributes.Clear();
                    searchRequest.Attributes.Add(currentRange);
                }
                else
                {
                    //Something went wrong here.
                    yield break;
                }
            }
        }

        /// <summary>
        ///     Takes a host in most applicable forms from AD and attempts to resolve it into a SID.
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public async Task<string> ResolveHostToSid(string hostname, string domain)
        {
            var strippedHost = Helpers.StripServicePrincipalName(hostname).ToUpper().TrimEnd('$');
            if (string.IsNullOrEmpty(strippedHost))
            {
                return null;
            }

            if (_hostResolutionMap.TryGetValue(strippedHost, out var sid)) return sid;

            var normalDomain = NormalizeDomainName(domain);

            string tempName;
            string tempDomain = null;

            //Step 1: Handle non-IP address values
            if (!IPAddress.TryParse(strippedHost, out _))
            {
                // Format: ABC.TESTLAB.LOCAL
                if (strippedHost.Contains("."))
                {
                    var split = strippedHost.Split('.');
                    tempName = split[0];
                    tempDomain = string.Join(".", split.Skip(1).ToArray());
                }
                // Format: WINDOWS
                else
                {
                    tempName = strippedHost;
                    tempDomain = normalDomain;
                }

                // Add $ to the end of the name to match how computers are stored in AD
                tempName = $"{tempName}$".ToUpper();
                var principal = ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    _hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }

            //Step 2: Try NetWkstaGetInfo
            //Next we'll try calling NetWkstaGetInfo in hopes of getting the NETBIOS name directly from the computer
            //We'll use the hostname that we started with instead of the one from our previous step
            var workstationInfo = await GetWorkstationInfo(strippedHost);
            if (workstationInfo.HasValue)
            {
                tempName = workstationInfo.Value.ComputerName;
                tempDomain = workstationInfo.Value.LanGroup;

                if (string.IsNullOrEmpty(tempDomain))
                    tempDomain = normalDomain;

                if (!string.IsNullOrEmpty(tempName))
                {
                    //Append the $ to indicate this is a computer
                    tempName = $"{tempName}$".ToUpper();
                    var principal = ResolveAccountName(tempName, tempDomain);
                    sid = principal?.ObjectIdentifier;
                    if (sid != null)
                    {
                        _hostResolutionMap.TryAdd(strippedHost, sid);
                        return sid;
                    }
                }
            }

            //Step 3: Socket magic
            // Attempt to request the NETBIOS name of the computer directly
            if (RequestNETBIOSNameFromComputer(strippedHost, normalDomain, out tempName))
            {
                tempDomain ??= normalDomain;
                tempName = $"{tempName}$".ToUpper();

                var principal = ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    _hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }

            //Try DNS resolution next
            string resolvedHostname;
            try
            {
                resolvedHostname = (await Dns.GetHostEntryAsync(strippedHost)).HostName;
            }
            catch
            {
                resolvedHostname = null;
            }

            if (resolvedHostname != null)
            {
                var splitName = resolvedHostname.Split('.');
                tempName = $"{splitName[0]}$".ToUpper();
                tempDomain = string.Join(".", splitName.Skip(1));

                var principal = ResolveAccountName(tempName, tempDomain);
                sid = principal?.ObjectIdentifier;
                if (sid != null)
                {
                    _hostResolutionMap.TryAdd(strippedHost, sid);
                    return sid;
                }
            }

            //If we get here, everything has failed, and life is very sad.
            tempName = strippedHost;
            tempDomain = normalDomain;

            if (tempName.Contains("."))
            {
                _hostResolutionMap.TryAdd(strippedHost, tempName);
                return tempName;
            }

            tempName = $"{tempName}.{tempDomain}";
            _hostResolutionMap.TryAdd(strippedHost, tempName);
            return tempName;
        }

        /// <summary>
        ///     Attempts to convert a bare account name (usually from session enumeration) to its corresponding ID and object type
        /// </summary>
        /// <param name="name"></param>
        /// <param name="domain"></param>
        /// <returns></returns>
        public TypedPrincipal ResolveAccountName(string name, string domain)
        {
            if (string.IsNullOrWhiteSpace(name))
                return null;

            if (Cache.GetPrefixedValue(name, domain, out var id) && Cache.GetIDType(id, out var type))
                return new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                };

            var d = NormalizeDomainName(domain);
            var result = QueryLDAP($"(samaccountname={name})", SearchScope.Subtree,
                CommonProperties.TypeResolutionProps,
                d).DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
            {
                _log.LogDebug("ResolveAccountName - unable to get result for {Name}", name);
                return null;
            }

            type = result.GetLabel();
            id = result.GetObjectIdentifier();

            if (id == null)
            {
                _log.LogDebug("ResolveAccountName - could not retrieve ID on {DN} for {Name}", result.DistinguishedName,
                    name);
                return null;
            }

            Cache.AddPrefixedValue(name, domain, id);
            Cache.AddType(id, type);

            id = ConvertWellKnownPrincipal(id, domain);

            return new TypedPrincipal
            {
                ObjectIdentifier = id,
                ObjectType = type
            };
        }

        /// <summary>
        ///     Attempts to convert a distinguishedname to its corresponding ID and object type.
        /// </summary>
        /// <param name="dn">DistinguishedName</param>
        /// <returns>A <c>TypedPrincipal</c> object with the SID and Label</returns>
        public TypedPrincipal ResolveDistinguishedName(string dn)
        {
            if (Cache.GetConvertedValue(dn, out var id) && Cache.GetIDType(id, out var type))
                return new TypedPrincipal
                {
                    ObjectIdentifier = id,
                    ObjectType = type
                };

            var domain = Helpers.DistinguishedNameToDomain(dn);
            var result = QueryLDAP("(objectclass=*)", SearchScope.Base, CommonProperties.TypeResolutionProps, domain,
                    adsPath: dn)
                .DefaultIfEmpty(null).FirstOrDefault();

            if (result == null)
            {
                _log.LogDebug("ResolveDistinguishedName - No result for {DN}", dn);
                return null;
            }

            id = result.GetObjectIdentifier();
            if (id == null)
            {
                _log.LogDebug("ResolveDistinguishedName - could not retrieve object identifier from {DN}", dn);
                return null;
            }

            if (GetWellKnownPrincipal(id, domain, out var principal)) return principal;

            type = result.GetLabel();

            Cache.AddConvertedValue(dn, id);
            Cache.AddType(id, type);

            id = ConvertWellKnownPrincipal(id, domain);

            return new TypedPrincipal
            {
                ObjectIdentifier = id,
                ObjectType = type
            };
        }

        /// <summary>
        ///     Queries LDAP using LDAPQueryOptions
        /// </summary>
        /// <param name="options"></param>
        /// <returns></returns>
        public IEnumerable<ISearchResultEntry> QueryLDAP(LDAPQueryOptions options)
        {
            return QueryLDAP(
                options.Filter,
                options.Scope,
                options.Properties,
                options.CancellationToken,
                options.DomainName,
                options.IncludeAcl,
                options.ShowDeleted,
                options.AdsPath,
                options.GlobalCatalog,
                options.SkipCache,
                options.ThrowException
            );
        }

        /// <summary>
        ///     Performs an LDAP query using the parameters specified by the user.
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="cancellationToken">Cancellation Token</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">
        ///     Skip the connection cache and force a new connection. You must dispose of this connection
        ///     yourself.
        /// </param>
        /// <param name="throwException">Throw exceptions rather than logging the errors directly</param>
        /// <returns>All LDAP search results matching the specified parameters</returns>
        /// <exception cref="LDAPQueryException">
        ///     Thrown when an error occurs during LDAP query (only when throwException = true)
        /// </exception>
        public IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, CancellationToken cancellationToken, string domainName = null, bool includeAcl = false,
            bool showDeleted = false, string adsPath = null, bool globalCatalog = false, bool skipCache = false,
            bool throwException = false)
        {
            var queryParams = SetupLDAPQueryFilter(
                ldapFilter, scope, props, includeAcl, domainName, includeAcl, adsPath, globalCatalog, skipCache);

            if (queryParams.Exception != null)
            {
                _log.LogWarning("Failed to setup LDAP Query Filter: {Message}", queryParams.Exception.Message);
                if (throwException)
                    throw new LDAPQueryException("Failed to setup LDAP Query Filter", queryParams.Exception);
                yield break;
            }

            var conn = queryParams.Connection;
            var request = queryParams.SearchRequest;
            var pageControl = queryParams.PageControl;

            PageResultResponseControl pageResponse = null;
            var backoffDelay = MinBackoffDelay;
            var retryCount = 0;
            while (true)
            {
                if (cancellationToken.IsCancellationRequested)
                    yield break;

                SearchResponse response;
                try
                {
                    _log.LogTrace("Sending LDAP request for {Filter}", ldapFilter);
                    response = (SearchResponse)conn.SendRequest(request);
                    if (response != null)
                        pageResponse = (PageResultResponseControl)response.Controls
                            .Where(x => x is PageResultResponseControl).DefaultIfEmpty(null).FirstOrDefault();
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.ServerDown &&
                                               retryCount < MaxRetries)
                {
                    /*A ServerDown exception indicates that our connection is no longer valid for one of many reasons.
                    However, this function is generally called by multiple threads, so we need to be careful in recreating
                    the connection. Using a semaphore, we can ensure that only one thread is actually recreating the connection
                    while the other threads that hit the ServerDown exception simply wait. The initial caller will hold the semaphore
                    and do a backoff delay before trying to make a new connection which will replace the existing connection in the
                    _ldapConnections cache. Other threads will retrieve the new connection from the cache instead of making a new one
                    This minimizes overhead of new connections while still fixing our core problem.*/
                    
                    //Always increment retry count
                    retryCount++;

                    //Attempt to acquire a lock
                    if (Monitor.TryEnter(_lockObj))
                    {
                        //If we've acquired the lock, we want to immediately signal our reset event so everyone else waits
                        _connectionResetEvent.Reset();
                        try
                        {
                            //Sleep for our backoff
                            Thread.Sleep(backoffDelay);
                            //Explicitly skip the cache so we don't get the same connection back
                            conn = CreateNewConnection(domainName, globalCatalog, true).Connection;
                            if (conn == null)
                            {
                                _log.LogError(
                                    "Unable to create replacement ldap connection for ServerDown exception. Breaking loop");
                                yield break;
                            }

                            _log.LogInformation("Created new LDAP connection after receiving ServerDown from server");
                        }
                        finally
                        {
                            //Reset our event + release the lock
                            _connectionResetEvent.Set();
                            Monitor.Exit(_lockObj);
                        }
                    }
                    else
                    {
                        //If someone else is holding the reset event, we want to just wait and then pull the newly created connection out of the cache
                        //This event will be released after the first entrant thread is done making a new connection
                        //The thread.sleep is to prevent a potential, very unlikely race
                        Thread.Sleep(50);
                        _connectionResetEvent.WaitOne();
                        conn = CreateNewConnection(domainName, globalCatalog).Connection;
                    }

                    backoffDelay = GetNextBackoff(retryCount);
                    continue;
                }
                catch (LdapException le) when (le.ErrorCode == (int)LdapErrorCodes.Busy && retryCount < MaxRetries)
                {
                    retryCount++;
                    backoffDelay = GetNextBackoff(retryCount);
                    continue;
                }
                catch (LdapException le)
                {
                    if (le.ErrorCode != (int)LdapErrorCodes.LocalError)
                    {
                        if (throwException)
                        {
                            throw new LDAPQueryException(
                                $"LDAP Exception in Loop: {le.ErrorCode}. {le.ServerErrorMessage}. {le.Message}. Filter: {ldapFilter}. Domain: {domainName}",
                                le);
                        }

                        _log.LogWarning(le,
                            "LDAP Exception in Loop: {ErrorCode}. {ServerErrorMessage}. {Message}. Filter: {Filter}. Domain: {Domain}",
                            le.ErrorCode, le.ServerErrorMessage, le.Message, ldapFilter, domainName);
                    }

                    yield break;
                }
                catch (Exception e)
                {
                    _log.LogWarning(e, "Exception in LDAP loop for {Filter} and {Domain}", ldapFilter, domainName);
                    if (throwException)
                        throw new LDAPQueryException($"Exception in LDAP loop for {ldapFilter} and {domainName}", e);

                    yield break;
                }

                if (cancellationToken.IsCancellationRequested)
                    yield break;

                if (response == null || pageResponse == null)
                    continue;

                foreach (SearchResultEntry entry in response.Entries)
                {
                    if (cancellationToken.IsCancellationRequested)
                        yield break;

                    yield return new SearchResultEntryWrapper(entry, this);
                }

                if (pageResponse.Cookie.Length == 0 || response.Entries.Count == 0 ||
                    cancellationToken.IsCancellationRequested)
                    yield break;

                pageControl.Cookie = pageResponse.Cookie;
            }
        }

        private LdapConnectionWrapper CreateNewConnection(string domainName = null, bool globalCatalog = false,
            bool skipCache = false)
        {
            var task = Task.Run(() => CreateLDAPConnectionWrapper(domainName, skipCache, _ldapConfig.AuthType, globalCatalog));

            try
            {
                return task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        ///     Performs an LDAP query using the parameters specified by the user.
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">
        ///     Skip the connection cache and force a new connection. You must dispose of this connection
        ///     yourself.
        /// </param>
        /// <param name="throwException">Throw exceptions rather than logging the errors directly</param>
        /// <returns>All LDAP search results matching the specified parameters</returns>
        /// <exception cref="LDAPQueryException">
        ///     Thrown when an error occurs during LDAP query (only when throwException = true)
        /// </exception>
        public virtual IEnumerable<ISearchResultEntry> QueryLDAP(string ldapFilter, SearchScope scope,
            string[] props, string domainName = null, bool includeAcl = false, bool showDeleted = false,
            string adsPath = null, bool globalCatalog = false, bool skipCache = false, bool throwException = false)
        {
            return QueryLDAP(ldapFilter, scope, props, new CancellationToken(), domainName, includeAcl, showDeleted,
                adsPath, globalCatalog, skipCache, throwException);
        }

        private static TimeSpan GetNextBackoff(int retryCount)
        {
            return TimeSpan.FromSeconds(Math.Min(
                MinBackoffDelay.TotalSeconds * Math.Pow(BackoffDelayMultiplier, retryCount),
                MaxBackoffDelay.TotalSeconds));
        }

        /// <summary>
        ///     Gets the forest associated with a domain.
        ///     If no domain is provided, defaults to current domain
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public virtual Forest GetForest(string domainName = null)
        {
            try
            {
                if (domainName == null && _ldapConfig.Username == null)
                    return Forest.GetCurrentForest();

                var domain = GetDomain(domainName);
                return domain?.Forest;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        ///     Creates a new ActiveDirectorySecurityDescriptor
        ///     Function created for testing purposes
        /// </summary>
        /// <returns></returns>
        public ActiveDirectorySecurityDescriptor MakeSecurityDescriptor()
        {
            return new ActiveDirectorySecurityDescriptor(new ActiveDirectorySecurity());
        }

        public string BuildLdapPath(string dnPath, string domainName)
        {
            //Check our cached info for a fast check
            if (CachedDomainInfo.TryGetValue(domainName, out var info))
            {
                return $"{dnPath},{info.DomainSearchBase}";
            }
            var domain = GetDomain(domainName)?.Name;
            if (domain == null)
                return null;

            var adPath = $"{dnPath},DC={domain.Replace(".", ",DC=")}";
            return adPath;
        }

        /// <summary>
        ///     Tests the current LDAP config to ensure its valid by pulling a domain object
        /// </summary>
        /// <returns>True if connection was successful, else false</returns>
        public bool TestLDAPConfig(string domain)
        {
            var filter = new LDAPFilter();
            filter.AddDomains();

            _log.LogTrace("Testing LDAP connection for domain {Domain}", domain);
            var result = QueryLDAP(filter.GetFilter(), SearchScope.Subtree, CommonProperties.ObjectID, domain,
                    throwException: true)
                .DefaultIfEmpty(null).FirstOrDefault();
            _log.LogTrace("Result object from LDAP connection test is {DN}", result?.DistinguishedName ?? "null");
            return result != null;
        }

        /// <summary>
        ///     Gets the domain object associated with the specified domain name.
        ///     Defaults to current domain if none specified
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public virtual Domain GetDomain(string domainName = null)
        {
            var cacheKey = domainName ?? NullCacheKey;
            if (_domainCache.TryGetValue(cacheKey, out var domain)) return domain;

            try
            {
                DirectoryContext context;
                if (_ldapConfig.Username != null)
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName, _ldapConfig.Username,
                            _ldapConfig.Password)
                        : new DirectoryContext(DirectoryContextType.Domain, _ldapConfig.Username,
                            _ldapConfig.Password);
                else
                    context = domainName != null
                        ? new DirectoryContext(DirectoryContextType.Domain, domainName)
                        : new DirectoryContext(DirectoryContextType.Domain);

                domain = Domain.GetDomain(context);
            }
            catch (Exception e)
            {
                _log.LogDebug(e, "GetDomain call failed at {StackTrace}", new StackFrame());
                domain = null;
            }

            _domainCache.TryAdd(cacheKey, domain);
            return domain;
        }

        /// <summary>
        ///     Setup LDAP query for filter
        /// </summary>
        /// <param name="ldapFilter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="props">LDAP properties to fetch for each object</param>
        /// <param name="includeAcl">Include the DACL and Owner values in the NTSecurityDescriptor</param>
        /// <param name="domainName">Domain to query</param>
        /// <param name="showDeleted">Include deleted objects</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="globalCatalog">Use the global catalog instead of the regular LDAP server</param>
        /// <param name="skipCache">
        ///     Skip the connection cache and force a new connection. You must dispose of this connection
        ///     yourself.
        /// </param>
        /// <returns>Tuple of LdapConnection, SearchRequest, PageResultRequestControl and LDAPQueryException</returns>
        // ReSharper disable once MemberCanBePrivate.Global
        internal LDAPQueryParams SetupLDAPQueryFilter(
            string ldapFilter,
            SearchScope scope, string[] props, bool includeAcl = false, string domainName = null,
            bool showDeleted = false,
            string adsPath = null, bool globalCatalog = false, bool skipCache = false)
        {
            _log.LogTrace("Creating ldap connection for {Target} with filter {Filter}",
                globalCatalog ? "Global Catalog" : "DC", ldapFilter);
            var task = Task.Run(() => CreateLDAPConnectionWrapper(domainName, skipCache, _ldapConfig.AuthType, globalCatalog));

            var queryParams = new LDAPQueryParams();

            LdapConnectionWrapper connWrapper;
            try
            {
                connWrapper = task.ConfigureAwait(false).GetAwaiter().GetResult();
            }
            catch (NoLdapDataException)
            {
                var errorString =
                    $"Successfully connected via LDAP to {domainName ?? "Default Domain"} but no data received. This is most likely due to permissions or using kerberos authentication across trusts.";
                queryParams.Exception = new LDAPQueryException(errorString, null);
                return queryParams;
            }
            catch (LdapAuthenticationException e)
            {
                var errorString =
                    $"Failed to connect via LDAP to {domainName ?? "Default Domain"}: Authentication is invalid";
                queryParams.Exception = new LDAPQueryException(errorString, e.InnerException);
                return queryParams;
            }
            catch (LdapConnectionException e)
            {
                var errorString =
                    $"Failed to connect via LDAP to {domainName ?? "Default Domain"}: {e.InnerException.Message} (Code: {e.ErrorCode}";
                queryParams.Exception = new LDAPQueryException(errorString, e.InnerException);
                return queryParams;
            }

            var conn = connWrapper.Connection;

            //If we get a null connection, something went wrong, but we don't have an error to go with it for whatever reason
            if (conn == null)
            {
                var errorString =
                    $"LDAP connection is null for filter {ldapFilter} and domain {domainName ?? "Default Domain"}";
                queryParams.Exception = new LDAPQueryException(errorString);
                return queryParams;
            }

            SearchRequest request;

            try
            {
                request = CreateSearchRequest(ldapFilter, scope, props, connWrapper.DomainInfo, adsPath, showDeleted);
            }
            catch (LDAPQueryException ldapQueryException)
            {
                queryParams.Exception = ldapQueryException;
                return queryParams;
            }

            if (request == null)
            {
                var errorString =
                    $"Search request is null for filter {ldapFilter} and domain {domainName ?? "Default Domain"}";
                queryParams.Exception = new LDAPQueryException(errorString);
                return queryParams;
            }

            var pageControl = new PageResultRequestControl(500);
            request.Controls.Add(pageControl);

            if (includeAcl)
                request.Controls.Add(new SecurityDescriptorFlagControl
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
                });

            queryParams.Connection = conn;
            queryParams.SearchRequest = request;
            queryParams.PageControl = pageControl;

            return queryParams;
        }

        private Group GetBaseEnterpriseDC(string domain)
        {
            var forest = GetForest(domain)?.Name;
            if (forest == null) _log.LogWarning("Error getting forest, ENTDC sid is likely incorrect");
            var g = new Group { ObjectIdentifier = $"{forest}-S-1-5-9".ToUpper() };
            g.Properties.Add("name", $"ENTERPRISE DOMAIN CONTROLLERS@{forest ?? "UNKNOWN"}".ToUpper());
            g.Properties.Add("domainsid", GetSidFromDomainName(forest));
            g.Properties.Add("domain", forest);
            return g;
        }

        /// <summary>
        ///     Updates the config for querying LDAP
        /// </summary>
        /// <param name="config"></param>
        public void UpdateLDAPConfig(LDAPConfig config)
        {
            _ldapConfig = config;
        }

        private string GetDomainNameFromSidLdap(string sid)
        {
            var hexSid = Helpers.ConvertSidToHexSid(sid);

            if (hexSid == null)
                return null;

            //Search using objectsid first
            var result =
                QueryLDAP($"(&(objectclass=domain)(objectsid={hexSid}))", SearchScope.Subtree,
                    new[] { "distinguishedname" }, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = Helpers.DistinguishedNameToDomain(result.DistinguishedName);
                return domainName;
            }

            //Try trusteddomain objects with the securityidentifier attribute
            result =
                QueryLDAP($"(&(objectclass=trusteddomain)(securityidentifier={sid}))", SearchScope.Subtree,
                    new[] { "cn" }, globalCatalog: true).DefaultIfEmpty(null).FirstOrDefault();

            if (result != null)
            {
                var domainName = result.GetProperty(LDAPProperties.CanonicalName);
                return domainName;
            }

            //We didn't find anything so just return null
            return null;
        }

        /// <summary>
        ///     Uses a socket and a set of bytes to request the NETBIOS name from a remote computer
        /// </summary>
        /// <param name="server"></param>
        /// <param name="domain"></param>
        /// <param name="netbios"></param>
        /// <returns></returns>
        private static bool RequestNETBIOSNameFromComputer(string server, string domain, out string netbios)
        {
            var receiveBuffer = new byte[1024];
            var requestSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                //Set receive timeout to 1 second
                requestSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 1000);
                EndPoint remoteEndpoint;

                //We need to create an endpoint to bind too. If its an IP, just use that.
                if (IPAddress.TryParse(server, out var parsedAddress))
                    remoteEndpoint = new IPEndPoint(parsedAddress, 137);
                else
                    //If its not an IP, we're going to try and resolve it from DNS
                    try
                    {
                        IPAddress address;
                        if (server.Contains("."))
                            address = Dns
                                .GetHostAddresses(server).First(x => x.AddressFamily == AddressFamily.InterNetwork);
                        else
                            address = Dns.GetHostAddresses($"{server}.{domain}")[0];

                        if (address == null)
                        {
                            netbios = null;
                            return false;
                        }

                        remoteEndpoint = new IPEndPoint(address, 137);
                    }
                    catch
                    {
                        //Failed to resolve an IP, so return null
                        netbios = null;
                        return false;
                    }

                var originEndpoint = new IPEndPoint(IPAddress.Any, 0);
                requestSocket.Bind(originEndpoint);

                try
                {
                    requestSocket.SendTo(NameRequest, remoteEndpoint);
                    var receivedByteCount = requestSocket.ReceiveFrom(receiveBuffer, ref remoteEndpoint);
                    if (receivedByteCount >= 90)
                    {
                        netbios = new ASCIIEncoding().GetString(receiveBuffer, 57, 16).Trim('\0', ' ');
                        return true;
                    }

                    netbios = null;
                    return false;
                }
                catch (SocketException)
                {
                    netbios = null;
                    return false;
                }
            }
            finally
            {
                //Make sure we close the socket if its open
                requestSocket.Close();
            }
        }

        /// <summary>
        ///     Calls the NetWkstaGetInfo API on a hostname
        /// </summary>
        /// <param name="hostname"></param>
        /// <returns></returns>
        private async Task<NetAPIStructs.WorkstationInfo100?> GetWorkstationInfo(string hostname)
        {
            if (!await _portScanner.CheckPort(hostname))
                return null;

            var result = NetAPIMethods.NetWkstaGetInfo(hostname);
            if (result.IsSuccess) return result.Value;

            return null;
        }

        /// <summary>
        ///     Creates a SearchRequest object for use in querying LDAP.
        /// </summary>
        /// <param name="filter">LDAP filter</param>
        /// <param name="scope">SearchScope to query</param>
        /// <param name="attributes">LDAP properties to fetch for each object</param>
        /// <param name="domainInfo">Domain info object which is created alongside the LDAP connection</param>
        /// <param name="adsPath">ADS path to limit the query too</param>
        /// <param name="showDeleted">Include deleted objects in results</param>
        /// <returns>A built SearchRequest</returns>
        private SearchRequest CreateSearchRequest(string filter, SearchScope scope, string[] attributes,
            DomainInfo domainInfo, string adsPath = null, bool showDeleted = false)
        {
            var adPath = adsPath?.Replace("LDAP://", "") ?? domainInfo.DomainSearchBase;

            var request = new SearchRequest(adPath, filter, scope, attributes);
            request.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));
            if (showDeleted)
                request.Controls.Add(new ShowDeletedControl());

            return request;
        }
        
        private LdapConnection CreateConnectionHelper(string directoryIdentifier, bool ssl, AuthType authType, bool globalCatalog)
        {
            var port = globalCatalog ? _ldapConfig.GetGCPort(ssl) : _ldapConfig.GetPort(ssl);
            var identifier = new LdapDirectoryIdentifier(directoryIdentifier, port, false, false);
            var connection = new LdapConnection(identifier) { Timeout = new TimeSpan(0, 0, 5, 0) };
            SetupLdapConnection(connection, true, authType);
            return connection;
        }

        private static void CheckAndThrowException(LdapException ldapException)
        {
            //A null error code with success false indicates that we successfully created a connection but got no data back, this is generally because our AuthType isn't compatible.
            //AuthType Kerberos will only work across trusts in very specific scenarios. Alternatively, we don't have read rights.
            //Throw this exception for clients to handle
            if (ldapException.ErrorCode is (int)LdapErrorCodes.KerberosAuthType or (int)ResultCode.InsufficientAccessRights)
            {
                throw new NoLdapDataException(ldapException.ErrorCode);
            }

            //We shouldn't ever hit this in theory, but we'll error out if its the case
            if (ldapException.ErrorCode is (int)ResultCode.InappropriateAuthentication)
            {
                throw new LdapAuthenticationException(ldapException);
            }

            //Any other error we dont have specific ways to handle
            if (ldapException.ErrorCode != (int)ResultCode.Unavailable && ldapException.ErrorCode != (int)ResultCode.Busy)
            {
                throw new LdapConnectionException(ldapException);
            }
        }

        private string ResolveDomainToFullName(string domain)
        {
            if (string.IsNullOrEmpty(domain))
            {
                return GetDomain()?.Name.ToUpper().Trim();
            }
            
            if (CachedDomainInfo.TryGetValue(domain.ToUpper(), out var info))
            {
                return info.DomainFQDN;
            }

            return GetDomain(domain)?.Name.ToUpper().Trim();
        }

        /// <summary>
        ///     Creates an LDAP connection with appropriate options based off the ldap configuration. Caches connections
        /// </summary>
        /// <param name="domainName">The domain to connect too</param>
        /// <param name="skipCache">Skip the connection cache</param>
        /// <param name="authType">Auth type to use. Defaults to Kerberos. Use Negotiate for netonly/cross trust(forest) scenarios</param>
        /// <param name="globalCatalog">Use global catalog or not</param>
        /// <returns>A connected LDAP connection or null</returns>

        private async Task<LdapConnectionWrapper> CreateLDAPConnectionWrapper(string domainName = null, bool skipCache = false,
            AuthType authType = AuthType.Kerberos, bool globalCatalog = false)
        {
            // Step 1: If domain passed in is non-null, skip this step
            // - Call GetDomain with a null domain to get the user's current domain
            // Step 2: Take domain passed in to the function or resolved from step 1
            // - Try an ldap connection on SSL
            // - If ServerUnavailable - Try an ldap connection on non-SSL
            //     Step 3: Pass the domain to GetDomain to resolve to a better name (potentially)
            //     - If we get a better name, repeat step 2 with the new name
            //     Step 4:
            // - Use GetDomain to get a domain object along with a list of domain controllers
            // - Try the primary domain controller on both ssl/non-ssl
            // - Loop over domain controllers and try each on ssl/non-ssl
            
            //If a server has been manually specified, we should never get past this block for opsec reasons
            if (_ldapConfig.Server != null)
            {
                if (!skipCache)
                {
                    if (GetCachedConnection(_ldapConfig.Server, globalCatalog, out var conn))
                    {
                        return conn;
                    }
                }
                
                var singleServerConn = CreateLDAPConnection(_ldapConfig.Server, authType, globalCatalog);
                if (singleServerConn == null) return new LdapConnectionWrapper()
                {
                    Connection = null,
                    DomainInfo = null
                };
                var cacheKey = new LDAPConnectionCacheKey(_ldapConfig.Server, globalCatalog);
                _ldapConnections.AddOrUpdate(cacheKey, singleServerConn, (_, ldapConnection) =>
                {
                    ldapConnection.Connection.Dispose();
                    return singleServerConn;
                });
                return singleServerConn;
            }
            
            //Take the incoming domain name and Upper/Trim it. If the name is null, we'll have to use GetDomain to figure out the user's domain context
            var domain = domainName?.ToUpper().Trim() ?? ResolveDomainToFullName(domainName);

            //If our domain is STILL null, we're not going to get anything reliable, so exit out
            if (domain == null)
            {
                return new LdapConnectionWrapper
                {
                    Connection = null,
                    DomainInfo = null
                };
            }
            
            if (!skipCache)
            {
                if (GetCachedConnection(domain, globalCatalog, out var conn))
                {
                    return conn;
                }
            }

            var connectionWrapper = CreateLDAPConnection(domain, authType, globalCatalog);
            //If our connection isn't null, it means we have a good connection
            if (connectionWrapper != null)
            {
                var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                {
                    ldapConnection.Connection.Dispose();
                    return connectionWrapper;
                });
                return connectionWrapper;
            }

            //If our incoming domain name wasn't null, try to re-resolve the name for a better potential match and then retry
            if (domainName != null)
            {
                var newDomain = ResolveDomainToFullName(domainName);
                if (!string.IsNullOrEmpty(newDomain) && !newDomain.Equals(domain, StringComparison.OrdinalIgnoreCase))
                {
                    //Set our domain name to the newly resolved value for future steps
                    domain = newDomain;
                    if (!skipCache)
                    {
                        //Check our cache again, maybe the new name works
                        if (GetCachedConnection(domain, globalCatalog, out var conn))
                        {
                            return conn;
                        }
                    }

                    connectionWrapper = CreateLDAPConnection(domain, authType, globalCatalog);
                    //If our connection isn't null, it means we have a good connection
                    if (connectionWrapper != null)
                    {
                        var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                        _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                        {
                            ldapConnection.Connection.Dispose();
                            return connectionWrapper;
                        });
                        return connectionWrapper;
                    }
                }
            }
            
            //Next step, look for domain controllers
            var domainObj = GetDomain(domain);
            if (domainObj?.Name == null)
            {
                return null;
            }

            //Start with the PDC of the domain and see if we can connect
            var pdc = domainObj.PdcRoleOwner.Name;
            connectionWrapper = await CreateLDAPConnectionWithPortCheck(pdc, authType, globalCatalog);
            if (connectionWrapper != null)
            {
                var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                {
                    ldapConnection.Connection.Dispose();
                    return connectionWrapper;
                });
                return connectionWrapper;
            }

            //Loop over all other domain controllers and see if we can make a good connection to any
            foreach (DomainController dc in domainObj.DomainControllers)
            {
                connectionWrapper = await CreateLDAPConnectionWithPortCheck(dc.Name, authType, globalCatalog);
                if (connectionWrapper != null)
                {
                    var cacheKey = new LDAPConnectionCacheKey(domain, globalCatalog);
                    _ldapConnections.AddOrUpdate(cacheKey, connectionWrapper, (_, ldapConnection) =>
                    {
                        ldapConnection.Connection.Dispose();
                        return connectionWrapper;
                    });
                    return connectionWrapper;
                }
            }

            return new LdapConnectionWrapper()
            {
                Connection = null,
                DomainInfo = null
            };
        }

        private bool GetCachedConnection(string domain, bool globalCatalog, out LdapConnectionWrapper connectionWrapper)
        {
            var domainName = domain;
            if (CachedDomainInfo.TryGetValue(domain.ToUpper(), out var resolved))
            {
                domainName = resolved.DomainFQDN;
            }
            var key = new LDAPConnectionCacheKey(domainName, globalCatalog);
            return _ldapConnections.TryGetValue(key, out connectionWrapper); 
        }

        private async Task<LdapConnectionWrapper> CreateLDAPConnectionWithPortCheck(string target, AuthType authType, bool globalCatalog)
        {
            if (globalCatalog)
            {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(true)) || (!_ldapConfig.ForceSSL &&
                        await _portScanner.CheckPort(target, _ldapConfig.GetGCPort(false))))
                {
                    return CreateLDAPConnection(target, authType, true);
                    
                }
            }
            else
            {
                if (await _portScanner.CheckPort(target, _ldapConfig.GetPort(true)) || (!_ldapConfig.ForceSSL && await _portScanner.CheckPort(target, _ldapConfig.GetPort(false))))
                {
                    return CreateLDAPConnection(target, authType, false);
                }
            }
            
            return null;
        }

        
        private LdapConnectionWrapper CreateLDAPConnection(string target, AuthType authType, bool globalCatalog)
        {
            //Lets build a new connection
            //Always try SSL first
            var connection = CreateConnectionHelper(target, true, authType, globalCatalog);
            var connectionResult = TestConnection(connection);
            DomainInfo info;

            if (connectionResult.Success)
            {
                var domain = connectionResult.DomainInfo.DomainFQDN;
                if (!CachedDomainInfo.ContainsKey(domain))
                {
                    var baseDomainInfo = connectionResult.DomainInfo;
                    baseDomainInfo.DomainSID =  GetDomainSidFromConnection(connection, baseDomainInfo);
                    baseDomainInfo.DomainNetbiosName = GetDomainNetbiosName(connection, baseDomainInfo);
                    _log.LogInformation("Got info for domain: {info}", baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainFQDN, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainNetbiosName, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainSID, baseDomainInfo);
                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainSID))
                    {
                        Cache.AddDomainSidMapping(baseDomainInfo.DomainFQDN, baseDomainInfo.DomainSID);
                        Cache.AddDomainSidMapping(baseDomainInfo.DomainSID, baseDomainInfo.DomainFQDN);
                        if (!string.IsNullOrEmpty(baseDomainInfo.DomainNetbiosName))
                        {
                            Cache.AddDomainSidMapping(baseDomainInfo.DomainNetbiosName, baseDomainInfo.DomainSID);    
                        }
                    }

                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainNetbiosName))
                    {
                        _netbiosCache.TryAdd(baseDomainInfo.DomainFQDN, baseDomainInfo.DomainNetbiosName);
                    }

                    info = baseDomainInfo;
                }
                else
                {
                    CachedDomainInfo.TryGetValue(domain, out info);
                }
                return new LdapConnectionWrapper
                {
                    Connection = connection,
                    DomainInfo = info
                };
            }

            CheckAndThrowException(connectionResult.Exception);

            //If we're not allowing fallbacks to LDAP from LDAPS, just return here
            if (_ldapConfig.ForceSSL)
            {
                return null;
            }
            //If we get to this point, it means we have an unsuccessful connection, but our error code doesn't indicate an outright failure
            //Try a new connection without SSL
            connection = CreateConnectionHelper(target, false, authType, globalCatalog);

            connectionResult = TestConnection(connection);
                
            if (connectionResult.Success)
            {
                var domain = connectionResult.DomainInfo.DomainFQDN;
                if (!CachedDomainInfo.ContainsKey(domain.ToUpper()))
                {
                    var baseDomainInfo = connectionResult.DomainInfo;
                    baseDomainInfo.DomainSID =  GetDomainSidFromConnection(connection, baseDomainInfo);
                    baseDomainInfo.DomainNetbiosName = GetDomainNetbiosName(connection, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainFQDN, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainNetbiosName, baseDomainInfo);
                    CachedDomainInfo.TryAdd(baseDomainInfo.DomainSID, baseDomainInfo);
                    
                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainSID))
                    {
                        Cache.AddDomainSidMapping(baseDomainInfo.DomainFQDN, baseDomainInfo.DomainSID);
                    }

                    if (!string.IsNullOrEmpty(baseDomainInfo.DomainNetbiosName))
                    {
                        Cache.AddDomainSidMapping(baseDomainInfo.DomainNetbiosName, baseDomainInfo.DomainSID);
                    }

                    info = baseDomainInfo;
                }else
                {
                    CachedDomainInfo.TryGetValue(domain, out info);
                }
                return new LdapConnectionWrapper
                {
                    Connection = connection,
                    DomainInfo = info
                };
            }
            
            CheckAndThrowException(connectionResult.Exception);
            return null;
        }

        private LdapConnectionTestResult TestConnection(LdapConnection connection)
        {
            try
            {
                //Attempt an initial bind. If this fails, likely auth is invalid, or its not a valid target
                connection.Bind();
            }
            catch (LdapException e)
            {
                connection.Dispose();
                return new LdapConnectionTestResult(false, e, null, null);
            }

            try
            {
                //Do an initial search request to get the rootDSE
                //This ldap filter is equivalent to (objectclass=*)
                var searchRequest = new SearchRequest("", new LDAPFilter().AddAllObjects().GetFilter(),
                    SearchScope.Base, null);
                searchRequest.Controls.Add(new SearchOptionsControl(SearchOption.DomainScope));

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                if (response?.Entries == null)
                {
                    connection.Dispose();
                    return new LdapConnectionTestResult(false, null, null, null);
                }

                if (response.Entries.Count == 0)
                {
                    connection.Dispose();
                    return new LdapConnectionTestResult(false, new LdapException((int)LdapErrorCodes.KerberosAuthType), null, null);
                }

                var entry = response.Entries[0];
                var baseDN = entry.GetProperty(LDAPProperties.RootDomainNamingContext).ToUpper().Trim();
                var configurationDN = entry.GetProperty(LDAPProperties.ConfigurationNamingContext).ToUpper().Trim();
                var domainname = Helpers.DistinguishedNameToDomain(baseDN).ToUpper().Trim();
                var servername = entry.GetProperty(LDAPProperties.ServerName);
                var compName = servername.Substring(0, servername.IndexOf(',')).Substring(3).Trim();
                var fullServerName = $"{compName}.{domainname}".ToUpper().Trim();

                return new LdapConnectionTestResult(true, null, new DomainInfo
                {
                    DomainConfigurationPath = configurationDN,
                    DomainSearchBase = baseDN,
                    DomainFQDN = domainname
                }, fullServerName);
            }
            catch (LdapException e)
            {
                try
                {
                    connection.Dispose();
                }
                catch
                {
                    //pass
                }
                return new LdapConnectionTestResult(false, e, null, null);
            }
        }
            
        public class LdapConnectionTestResult
        {
            public bool Success { get; set; }
            public LdapException Exception { get; set; }
            public DomainInfo DomainInfo { get; set; }
            public string ServerName { get; set; }

            public LdapConnectionTestResult(bool success, LdapException e, DomainInfo info, string server)
            {
                Success = success;
                Exception = e;
                DomainInfo = info;
                ServerName = server;
            }
        }

        private string GetDomainNetbiosName(LdapConnection connection, DomainInfo info)
        {
            try
            {
                var searchRequest = new SearchRequest($"CN=Partitions,{info.DomainConfigurationPath}",
                    "(&(nETBIOSName=*)(dnsRoot=*))",
                    SearchScope.Subtree, new[] { LDAPProperties.NetbiosName, LDAPProperties.DnsRoot });

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                if (response == null || response.Entries.Count == 0)
                {
                    return "";
                }

                foreach (SearchResultEntry entry in response.Entries)
                {
                    var root = entry.GetProperty(LDAPProperties.DnsRoot);
                    var netbios = entry.GetProperty(LDAPProperties.NetbiosName);
                    _log.LogInformation(root);
                    _log.LogInformation(netbios);

                    if (root.ToUpper().Equals(info.DomainFQDN))
                    {
                        return netbios.ToUpper();
                    }
                }

                return "";
            }
            catch (LdapException e)
            {
                _log.LogWarning("Failed grabbing netbios name from ldap for {domain}: {e}", info.DomainFQDN, e);
                return "";
            }
        }

        private string GetDomainSidFromConnection(LdapConnection connection, DomainInfo info)
        {
            try
            {
                //This ldap filter searches for domain controllers
                //Searches for any accounts with a UAC value inclusive of 8192 bitwise
                //8192 is the flag for SERVER_TRUST_ACCOUNT, which is set only on Domain Controllers
                var searchRequest = new SearchRequest(info.DomainSearchBase,
                    "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    SearchScope.Subtree, new[] { "objectsid"});

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                if (response == null || response.Entries.Count == 0)
                {
                    return "";
                }

                var entry = response.Entries[0];
                var sid = entry.GetSid();
                return sid.Substring(0, sid.LastIndexOf('-')).ToUpper();
            }
            catch (LdapException)
            {
                _log.LogWarning("Failed grabbing domainsid from ldap for {domain}", info.DomainFQDN);
                return "";
            }
        }
        
        private void SetupLdapConnection(LdapConnection connection, bool ssl, AuthType authType)
        {
            //These options are important!
            connection.SessionOptions.ProtocolVersion = 3;
            //Referral chasing does not work with paged searches 
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            if (ssl)
            {
                connection.SessionOptions.SecureSocketLayer = true;    
            }
            
            if (_ldapConfig.DisableSigning)
            {
                connection.SessionOptions.Sealing = false;
                connection.SessionOptions.Signing = false;
            }
            
            if (_ldapConfig.DisableCertVerification)
                connection.SessionOptions.VerifyServerCertificate = (_, _) => true;
            
            if (_ldapConfig.Username != null)
            {
                var cred = new NetworkCredential(_ldapConfig.Username, _ldapConfig.Password);
                connection.Credential = cred;
            }
            
            connection.AuthType = authType;
        }

        /// <summary>
        ///     Normalizes a domain name to its full DNS name
        /// </summary>
        /// <param name="domain"></param>
        /// <returns></returns>
        internal string NormalizeDomainName(string domain)
        {
            if (domain == null)
                return null;

            var resolved = domain;

            if (resolved.Contains("."))
                return domain.ToUpper();

            resolved = ResolveDomainNetbiosToDns(domain) ?? domain;

            return resolved.ToUpper();
        }

        /// <summary>
        ///     Turns a domain Netbios name into its FQDN using the DsGetDcName function (TESTLAB -> TESTLAB.LOCAL)
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        internal string ResolveDomainNetbiosToDns(string domainName)
        {
            var key = domainName.ToUpper();
            if (_netbiosCache.TryGetValue(key, out var flatName))
                return flatName;

            var domain = GetDomain(domainName);
            if (domain != null)
            {
                _netbiosCache.TryAdd(key, domain.Name);
                return domain.Name;
            }

            var computerName = _ldapConfig.Server;

            var dci = _nativeMethods.CallDsGetDcName(computerName, domainName);
            if (dci.IsSuccess)
            {
                flatName = dci.Value.DomainName;
                _netbiosCache.TryAdd(key, flatName);
                return flatName;
            }

            return domainName.ToUpper();
        }

        /// <summary>
        /// Gets the range retrieval limit for a domain
        /// </summary>
        /// <param name="domainName"></param>
        /// <param name="defaultRangeSize"></param>
        /// <returns></returns>
        public int GetDomainRangeSize(string domainName = null, int defaultRangeSize = 750)
        {
            var domainPath = DomainNameToDistinguishedName(domainName);
            //Default to a page size of 750 for safety
            if (domainPath == null)
            {
                _log.LogDebug("Unable to resolve domain {Domain} to distinguishedname to get page size",
                    domainName ?? "current domain");
                return defaultRangeSize;
            }

            if (_ldapRangeSizeCache.TryGetValue(domainPath.ToUpper(), out var parsedPageSize))
            {
                return parsedPageSize;
            }

            var configPath = CommonPaths.CreateDNPath(CommonPaths.QueryPolicyPath, domainPath);
            var enumerable = QueryLDAP("(objectclass=*)", SearchScope.Base, null, adsPath: configPath);
            var config = enumerable.DefaultIfEmpty(null).FirstOrDefault();
            var pageSize = config?.GetArrayProperty(LDAPProperties.LdapAdminLimits)
                .FirstOrDefault(x => x.StartsWith("MaxPageSize", StringComparison.OrdinalIgnoreCase));
            if (pageSize == null)
            {
                _log.LogDebug("No LDAPAdminLimits object found for {Domain}", domainName);
                _ldapRangeSizeCache.TryAdd(domainPath.ToUpper(), defaultRangeSize);
                return defaultRangeSize;
            }

            if (int.TryParse(pageSize.Split('=').Last(), out parsedPageSize))
            {
                _ldapRangeSizeCache.TryAdd(domainPath.ToUpper(), parsedPageSize);
                _log.LogInformation("Found page size {PageSize} for {Domain}", parsedPageSize,
                    domainName ?? "current domain");
                return parsedPageSize;
            }

            _log.LogDebug("Failed to parse pagesize for {Domain}, returning default", domainName ?? "current domain");

            _ldapRangeSizeCache.TryAdd(domainPath.ToUpper(), defaultRangeSize);
            return defaultRangeSize;
        }

        private string DomainNameToDistinguishedName(string domain)
        {
            var resolvedDomain = GetDomain(domain)?.Name ?? domain;
            return resolvedDomain == null ? null : $"DC={resolvedDomain.Replace(".", ",DC=")}";
        }

        private class ResolvedWellKnownPrincipal
        {
            public string DomainName { get; set; }
            public string WkpId { get; set; }
        }

        public string GetConfigurationPath(string domainName = null)
        {
            string path = domainName == null
                ? "LDAP://RootDSE"
                : $"LDAP://{NormalizeDomainName(domainName)}/RootDSE";

            DirectoryEntry rootDse;
            if (_ldapConfig.Username != null)
                rootDse = new DirectoryEntry(path, _ldapConfig.Username, _ldapConfig.Password);
            else
                rootDse = new DirectoryEntry(path);

            return $"{rootDse.Properties["configurationNamingContext"]?[0]}";
        }

        public string GetSchemaPath(string domainName)
        {
            string path = domainName == null
                ? "LDAP://RootDSE"
                : $"LDAP://{NormalizeDomainName(domainName)}/RootDSE";

            DirectoryEntry rootDse;
            if (_ldapConfig.Username != null)
                rootDse = new DirectoryEntry(path, _ldapConfig.Username, _ldapConfig.Password);
            else
                rootDse = new DirectoryEntry(path);

            return $"{rootDse.Properties["schemaNamingContext"]?[0]}";
        }

        public bool IsDomainController(string computerObjectId, string domainName)
        {
            var filter = new LDAPFilter().AddFilter(LDAPProperties.ObjectSID + "=" + computerObjectId, true)
                .AddFilter(CommonFilters.DomainControllers, true);
            var res = QueryLDAP(filter.GetFilter(), SearchScope.Subtree,
                CommonProperties.ObjectID, domainName: domainName);
            if (res.Count() > 0)
                return true;
            return false;
        }
    }
}