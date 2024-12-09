#nullable enable
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Diagnostics;
using System.Threading.Tasks;
using SharpHoundCommonLib.OutputTypes;
using System.Net;

namespace SharpHoundCommonLib.Processors
{
    [Flags]
    public enum EventLogCollection
    {
        InboundNtlmSessions,
        DomainControllerNtlmAuth,
    }

    public class EventLogProcessor(
         ILdapUtils utils,
         ILogger log,
         string host,
         string domain,
         EventLogCollection collectionType,
         int numDays = 7,
         int readEventDelayMs = 5,
         int readEventTimeoutMs = 10000,
         NetworkCredential? localAdminCredential = null
         )
    {
        private readonly ILdapUtils _utils = utils;
        private readonly string _host = host;
        private readonly string _domain = domain;
        private readonly EventLogCollection _collectType = collectionType;
        private readonly int _numDays = numDays;
        private readonly TimeSpan _readEventTimeoutMs = TimeSpan.FromMilliseconds(readEventTimeoutMs);
        private readonly int _readDelay = readEventDelayMs;
        private readonly ILogger _log = log;
        private NetworkCredential? _localAdminCred = localAdminCredential;

        #region Event Log XPath Queries
        /* Logic for non-DC machines:
         * - Collect from the Security event log
         * - Get 4624 events (Logon Events) in the last X days
         * - Filter where LogonType=3 (Network Logon) since for NTLM we're interested in inbound network auth attempts
         * - Filter on either of these:
         *   - NTLMv2 and KeyLength=0 (indicates signing is disabled)
         *   - NTLMV1 (doesn't support signing)
         *   
         * Example event XML data:
         * <EventData>
         *   <Data Name="SubjectUserSid">S-1-0-0</Data> 
         *   <Data Name="SubjectUserName">-</Data> 
         *   <Data Name="SubjectDomainName">-</Data> 
         *   <Data Name="SubjectLogonId">0x0</Data> 
         *   <Data Name="TargetUserSid">S-1-5-21-3821320868-1508310791-3575676346-1103</Data> 
         *   <Data Name="TargetUserName">itadmin</Data> 
         *   <Data Name="TargetDomainName">CORP</Data> 
         *   <Data Name="TargetLogonId">0x21eacfe9</Data> 
         *   <Data Name="LogonType">3</Data> 
         *   <Data Name="LogonProcessName">NtLmSsp</Data> 
         *   <Data Name="AuthenticationPackageName">NTLM</Data> 
         *   <Data Name="WorkstationName">WIN11</Data> 
         *   <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data> 
         *   <Data Name="TransmittedServices">-</Data> 
         *   <Data Name="LmPackageName">NTLM V2</Data> 
         *   <Data Name="KeyLength">0</Data> 
         *   <Data Name="ProcessId">0x0</Data> 
         *   <Data Name="ProcessName">-</Data> 
         *   <Data Name="IpAddress">192.168.230.101</Data> 
         *   <Data Name="IpPort">54303</Data> 
         *   <Data Name="ImpersonationLevel">%%1833</Data> 
         *   <Data Name="RestrictedAdminMode">-</Data> 
         *   <Data Name="RemoteCredentialGuard">-</Data> 
         *   <Data Name="TargetOutboundUserName">-</Data> 
         *   <Data Name="TargetOutboundDomainName">-</Data> 
         *   <Data Name="VirtualAccount">%%1843</Data> 
         *   <Data Name="TargetLinkedLogonId">0x0</Data> 
         *   <Data Name="ElevatedToken">%%1842</Data> 
         * </EventData>
         */
        private readonly string _noSigningXpathEvents = @"
<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>
      *[System[
        (EventID=4624)
        and
        (TimeCreated[timediff(@SystemTime) &lt;= {0}])
      ]]
      and
      *[EventData[
        (
          (Data[@Name='LogonType']=3)
          and
          (
            (Data[@Name='LmPackageName']='NTLM V2' and Data[@Name='KeyLength']=0)
            or
            (Data[@Name='LmPackageName']='NTLM V1')
          )
        )
      ]]
    </Select>
  </Query>
</QueryList>
".Trim();

        /* Logic for DC machines:
         * - Collect from the Security event log
         * - Get 4776 events (Logon Events) in the last X days. This event is only generated for NTLM auth.
         * - Filter on:
         *      Status=0 (Successful auth)
         *   
         * - Example event XML data:
          <Event>
            <EventData>
              <Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data> 
              <Data Name="TargetUserName">lowpriv</Data> 
              <Data Name="Workstation">DESKTOP-P8UDQ3B</Data> 
              <Data Name="Status">0x0</Data> 
            </EventData>
          </Event>
        */
        private readonly string _dcNtlmAuthXpathEvents = @"
<QueryList>
  <Query Id=""0"" Path=""Security"">
    <Select Path=""Security"">
      *[System[
        (EventID=4776)
        and
        (TimeCreated[timediff(@SystemTime) &lt;= {0}])
      ]]
      and
      *[EventData[
        (
          (Data[@Name='Status']=""0x0"")
        )
      ]]
    </Select>
  </Query>
</QueryList>
";
        #endregion // Event Log XPath Queries
        public ApiResult<NtlmSessionResult> ReadEvents()
        {
            var result = new NtlmSessionResult();
            string query;
            var timeFilterMs = TimeSpan.FromDays(_numDays).TotalMilliseconds;

            switch (_collectType)
            {
                case EventLogCollection.DomainControllerNtlmAuth:
                    query = String.Format(_dcNtlmAuthXpathEvents, timeFilterMs);
                    break;
                case EventLogCollection.InboundNtlmSessions:
                    query = String.Format(_noSigningXpathEvents, timeFilterMs);
                    break;
                default:
                    throw new InvalidOperationException("Invalid option");
            }


            try
            {
                var sw = Stopwatch.StartNew();
                result.Sessions = CollectEvents(query);
                sw.Stop();

                result.CollectionDurationMs = sw.ElapsedMilliseconds;

                _log.LogDebug($"Processed {result.Sessions.Count} event logs in {sw.Elapsed}. Event Log Collection Type: {_collectType}");

                return ApiResult<NtlmSessionResult>.CreateSuccess(result);
            }
            catch (UnauthorizedAccessException)
            {
                return ApiResult<NtlmSessionResult>.CreateError("Access Denied");
            }
            catch (Exception ex)
            {
                return ApiResult<NtlmSessionResult>.CreateError($"Unexpected exception: {ex}");
            }
        }

        private List<NtlmSession> CollectEvents(string query)
        {
            var ntlmSessions = new List<NtlmSession>();
            var dupCheck = new HashSet<string>();

            using EventLogReader logReader = GetEventLogReader(_host, "Security", query);

            int count = 0;

            for (var evnt = logReader.ReadEvent(_readEventTimeoutMs);
                evnt != null;
                evnt = logReader.ReadEvent())
            {
                count++;
                var eventId = (SecurityLogId)evnt.Id;
                var parsed = ProcessSecurityEvent(evnt, eventId).Result;
                // Don't return another if we've already got the info
                if (dupCheck.Add(GetHashString(parsed)))
                {
                    ntlmSessions.Add(parsed);
                }

                if (_readDelay > 0)
                {
                    System.Threading.Thread.Sleep(_readDelay);
                }
            }

            return ntlmSessions;
        }

        private string GetHashString(NtlmSession s)
        {
            return $"{s.AccountDomain}{s.AccountName}{s.AccountSid}{s.PackageName}{s.SourceIp}{s.SourceHost}";
        }

        private async Task<string?> ResolveNameToSid(string username, string domain)
        {
            var (matchSuccess, sids) = await _utils.GetGlobalCatalogMatches(username, domain);
            if (matchSuccess)
            {
                if (sids.Length > 1)
                {
                    _log.LogError("More than one SID was returned for the user '{user}'. SIDs: {sids}", username, string.Join(",", sids));
                    return null;
                }

                return sids[0];
            }
            else
            {
                var (success, principal) = await _utils.ResolveAccountName(username, domain);

                if (!success) return null;

                return principal.ObjectIdentifier;
            }
        }

        private async Task<NtlmSession> ProcessSecurityEvent(EventRecord evnt, SecurityLogId eventId)
        {
            NtlmSession session;

            switch (eventId)
            {
                case SecurityLogId.Logon:
                    session = NtlmSession.FromLogonEvent(_host, evnt);
                    return session;

                case SecurityLogId.ValidateCredential:

                    session = NtlmSession.FromValidateCredentialEvent(_host, evnt);

                    // The Validate Credential event does not return the domain or account sid
                    // so try and find those
                    var sid = await ResolveNameToSid(session.AccountName, _domain);

                    session.AccountSid = sid?.ToString();
                    session.AccountDomain = _domain;

                    return session;

                default:
                    throw new InvalidOperationException("Unhandled security event log ID");
            }
        }


        private EventLogReader GetEventLogReader(string host, string path, string query)
        {
            var eventsQuery = new EventLogQuery(path, PathType.LogName, query) { ReverseDirection = true };
            EventLogSession session;
            if (!string.IsNullOrEmpty(host))
            {

                if (_localAdminCred == null)
                {
                    session = new EventLogSession(
                        host,
                        null,
                        null,
                        null,
                        SessionAuthentication.Negotiate
                    );
                }
                else
                {
                    session = new EventLogSession(
                        host,
                        _localAdminCred.Domain,
                        _localAdminCred.UserName,
                        _localAdminCred.SecurePassword,
                        SessionAuthentication.Negotiate
                    );
                }

                eventsQuery.Session = session;
            }

            var logReader = new EventLogReader(eventsQuery);
            return logReader;
        }
    }

    public enum SecurityLogId
    {
        Logon = 4624,
        ValidateCredential = 4776
    }

    public enum SecurityLogLogonType : uint
    {
        Interactive = 2,        // logging on interactively.
        Network,                // logging using a network.
        Batch,                  // logon for a batch process.
        Service,                // logon for a service account.
        Proxy,                  // Not supported.
        Unlock,                 // Tattempt to unlock a workstation.
        NetworkCleartext,       // network logon with cleartext credentials
        NewCredentials,         // caller can clone its current token and specify new credentials for outbound connections
        RemoteInteractive,      // terminal server session that is both remote and interactive
        CachedInteractive,      // attempt to use the cached credentials without going out across the network
        CachedRemoteInteractive,// same as RemoteInteractive, except used internally for auditing purposes
        CachedUnlock            // attempt to unlock a workstation
    }
}
#nullable disable