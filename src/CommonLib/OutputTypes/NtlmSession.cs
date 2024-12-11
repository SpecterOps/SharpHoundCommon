#nullable enable
using SharpHoundCommonLib.Processors;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using SharpHoundCommonLib.Enums;

namespace SharpHoundCommonLib.OutputTypes {
    public class NtlmSessionResult {
        public List<NtlmSession>? Sessions { get; set; }
        public long CollectionDurationMs { get; set; }
    }

    public class NtlmSession(
        DateTime? timeCreatedUtc,
        SecurityLogId id,
        string? accountSid,
        string accountName,
        string? accountDomain,
        string sourceHost,
        string? sourceIp,
        string? sourcePort,
        string packageName
    ) {
        public DateTime? TimeCreatedUtc { get; set; } = timeCreatedUtc;
        public SecurityLogId Id { get; set; } = id;
        public string? AccountSid { get; set; } = accountSid;
        public string AccountName { get; set; } = accountName;
        public string? AccountDomain { get; set; } = accountDomain;
        public string SourceHost { get; set; } = sourceHost; // The host the auth originated from
        public string? SourceIp { get; set; } = sourceIp;
        public string? SourcePort { get; set; } = sourcePort;
        public string? PackageName { get; set; } = packageName;

        public override string ToString() {
            var targetUser = AccountDomain + "\\" + AccountName;
            var source = (SourceIp != null || SourcePort != null) ? $"{SourceIp}:{SourcePort}" : "";

            return ($"  {TimeCreatedUtc?.ToLocalTime()},{Id},{targetUser},{AccountSid},{SourceHost},,{PackageName}");
        }

        public static NtlmSession FromLogonEvent(EventRecord evnt) {
            if (evnt.Id != EventIds.LogonEvent)
                throw new ArgumentException("Not a logon event");

            //var subjectUserSid = eventDetail.Properties[0].Value.ToString();
            //var subjectUserName = eventDetail.Properties[1].Value.ToString();
            //var subjectDomainName = eventDetail.Properties[2].Value.ToString();
            //var subjectLogonId = eventDetail.Properties[3].Value.ToString();
            var targetUserSid = evnt.Properties[4].Value.ToString();
            var targetUserName = evnt.Properties[5].Value.ToString();
            var targetDomainName = evnt.Properties[6].Value.ToString();
            //var targetLogonId = eventDetail.Properties[7].Value.ToString();
            //var logonType = eventDetail.Properties[8].Value.ToString();
            //var logonType = $"{(SECURITY_LOGON_TYPE)(int.Parse(eventDetail.Properties[8].Value.ToString()))}";
            //var logonProcessName = eventDetail.Properties[9].Value.ToString();
            //var authenticationPackageName = eventDetail.Properties[10].Value.ToString();
            var workstationName = evnt.Properties[11].Value.ToString();
            //var logonGuid = eventDetail.Properties[12].Value.ToString();
            //var transmittedServices = eventDetail.Properties[13].Value.ToString();
            var lmPackageName = evnt.Properties[14].Value.ToString();
            //var keyLength = eventDetail.Properties[15].Value.ToString();
            //var processId = eventDetail.Properties[16].Value.ToString();
            //var processName = eventDetail.Properties[17].Value.ToString();
            var ipAddress = evnt.Properties[18].Value.ToString();
            var ipPort = evnt.Properties[19].Value.ToString();


            return new NtlmSession(
                evnt.TimeCreated?.ToUniversalTime(),
                SecurityLogId.Logon,
                targetUserSid,
                targetUserName,
                targetDomainName,
                workstationName,
                ipAddress,
                ipPort,
                lmPackageName
            );
        }

        public static NtlmSession FromValidateCredentialEvent(EventRecord evnt) {
            if (evnt.Id != EventIds.ValidateCredentialsEvent)
                throw new ArgumentException("Not a validate credential event");

            var packageName = evnt.Properties[0].Value.ToString();
            var targetUserName = evnt.Properties[1].Value.ToString();
            var workstation = evnt.Properties[2].Value.ToString();
            //var status = evt.Properties[3].Value.ToString();

            return new NtlmSession(
                evnt.TimeCreated?.ToUniversalTime(),
                SecurityLogId.Logon,
                null,
                targetUserName,
                null,
                workstation,
                null,
                null,
                packageName
            );
        }
    }
}
#nullable disable