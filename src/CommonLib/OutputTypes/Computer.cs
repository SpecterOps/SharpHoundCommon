using System.Collections.Generic;

namespace SharpHoundCommonLib.OutputTypes {
    /// <summary>
    ///     Represents a computer object in Active Directory. Contains all the properties BloodHound cares about
    /// </summary>
    public class Computer : OutputBase {
        public string PrimaryGroupSID { get; set; }
        public TypedPrincipal[] AllowedToDelegate { get; set; } = [];
        public TypedPrincipal[] AllowedToAct { get; set; } = [];
        public TypedPrincipal[] HasSIDHistory { get; set; } = [];
        public TypedPrincipal[] DumpSMSAPassword { get; set; } = [];
        public SessionAPIResult Sessions { get; set; } = new();
        public SessionAPIResult PrivilegedSessions { get; set; } = new();
        public SessionAPIResult RegistrySessions { get; set; } = new();
        public LocalGroupAPIResult[] LocalGroups { get; set; } = [];
        public UserRightsAssignmentAPIResult[] UserRights { get; set; } = [];
        public DCRegistryData DCRegistryData { get; set; } = new();
        public ComputerStatus Status { get; set; }
        public bool IsDC { get; set; }
        public bool UnconstrainedDelegation { get; set; }
        public string DomainSID { get; set; }

#pragma warning disable CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
        public ApiResult<bool> IsWebClientRunning { get; set; }
        public LdapService? LdapServices { get; set; }
        public ApiResult<SmbInfo>? SmbInfo { get; set; }
        public ApiResult<NtlmSessionResult>? NtlmSessions { get; set; }
#pragma warning restore CS8632 // The annotation for nullable reference types should only be used in code within a '#nullable' annotations context.
    }

    public class LdapService(
        bool hasLdap,
        bool hasLdaps,
        ApiResult<bool> isSigningRequired,
        ApiResult<bool> isChannelBindingRequired) {
        // Is the LDAP port accesible?
        public bool HasLdap { get; set; } = hasLdap;

        // Is the LDAPS port accessible?
        public bool HasLdaps { get; set; } = hasLdaps;

        // For LDAP, is signing required?
        public ApiResult<bool> IsSigningRequired { get; set; } = isSigningRequired;

        // For LDAPS, is EPA(ChannelBinding) required?
        public ApiResult<bool> IsChannelBindingDisabled { get; set; } = isChannelBindingRequired;

        public override string ToString() {
            return $"""
                    HasLdap: {HasLdap}
                    HasLdaps: {HasLdaps}
                    IsSigningRequired: {IsSigningRequired}
                    IsChannelBindingDisabled: {IsChannelBindingDisabled}
                    """;
        }
    }


    public class SmbInfo {
        public bool? SigningEnabled;
        public string OsVersion;
        public string OsBuild;
        public string DnsComputerName { get; internal set; }
    }

    public class DCRegistryData {
        public IntRegistryAPIResult CertificateMappingMethods { get; set; }
        public IntRegistryAPIResult StrongCertificateBindingEnforcement { get; set; }
    }

    public class ComputerStatus {
        public bool Connectable { get; set; }
        public string Error { get; set; }

        public static string NonWindowsOS => "NonWindowsOS";
        public static string NotActive => "NotActive";
        public static string PortNotOpen => "PortNotOpen";
        public static string Success => "Success";

        public CSVComputerStatus GetCSVStatus(string computerName) {
            return new CSVComputerStatus {
                Status = Error,
                Task = "CheckAvailability",
                ComputerName = computerName
            };
        }
    }
}