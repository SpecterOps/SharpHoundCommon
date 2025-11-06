namespace SharpHoundCommonLib.LDAPQueries
{
    public static class CommonProperties
    {
        public static readonly string[] TypeResolutionProps =
        {
            LDAPProperties.SAMAccountType, LDAPProperties.ObjectSID, LDAPProperties.ObjectGUID,
            LDAPProperties.ObjectClass, LDAPProperties.SAMAccountName, LDAPProperties.GroupMSAMembership,
            LDAPProperties.Flags
        };

        public static readonly string[] ObjectID = { LDAPProperties.ObjectSID, LDAPProperties.ObjectGUID };
        public static readonly string[] ObjectSID = { LDAPProperties.ObjectSID };
        public static readonly string[] GPCFileSysPath = { LDAPProperties.GPCFileSYSPath };

        public static readonly string[] BaseQueryProps =
        {
            LDAPProperties.ObjectSID, LDAPProperties.DistinguishedName, LDAPProperties.ObjectGUID,
            LDAPProperties.LegacyLAPSExpirationTime, LDAPProperties.LAPSExpirationTime, LDAPProperties.IsDeleted,
            LDAPProperties.UserAccountControl
        };

        public static readonly string[] GroupResolutionProps =
        {
            LDAPProperties.SAMAccountName, LDAPProperties.DistinguishedName, LDAPProperties.SAMAccountType,
            LDAPProperties.Members, LDAPProperties.CanonicalName, LDAPProperties.PrimaryGroupID,
            LDAPProperties.DNSHostName
        };

        public static readonly string[] ComputerMethodProps =
        {
            LDAPProperties.SAMAccountName, LDAPProperties.DistinguishedName, LDAPProperties.DNSHostName,
            LDAPProperties.SAMAccountType, LDAPProperties.OperatingSystem, LDAPProperties.PasswordLastSet,
            LDAPProperties.LastLogonTimestamp, LDAPProperties.ObjectGUID
        };

        public static readonly string[] ACLProps =
        {
            LDAPProperties.SAMAccountName, LDAPProperties.DistinguishedName, LDAPProperties.DNSHostName,
            LDAPProperties.SAMAccountType, LDAPProperties.SecurityDescriptor,
            LDAPProperties.DisplayName, LDAPProperties.ObjectClass, LDAPProperties.ObjectSID, LDAPProperties.Name
        };

        public static readonly string[] ObjectPropsProps =
        {
            LDAPProperties.SAMAccountName, LDAPProperties.DistinguishedName, LDAPProperties.SAMAccountType,
            LDAPProperties.PasswordLastSet, LDAPProperties.LastLogon, LDAPProperties.LastLogonTimestamp,
            LDAPProperties.ObjectSID,
            LDAPProperties.SIDHistory, LDAPProperties.DNSHostName, LDAPProperties.OperatingSystem,
            LDAPProperties.ServicePack, LDAPProperties.ServicePrincipalNames, LDAPProperties.DisplayName,
            LDAPProperties.Email, LDAPProperties.Title,
            LDAPProperties.HomeDirectory, LDAPProperties.Description, LDAPProperties.AdminCount,
            LDAPProperties.UserPassword, LDAPProperties.GPCFileSYSPath, LDAPProperties.ObjectClass,
            LDAPProperties.DomainFunctionalLevel, LDAPProperties.ObjectGUID, LDAPProperties.Name,
            LDAPProperties.GroupPolicyOptions, LDAPProperties.AllowedToDelegateTo,
            LDAPProperties.AllowedToActOnBehalfOfOtherIdentity, LDAPProperties.WhenCreated,
            LDAPProperties.HostServiceAccount, LDAPProperties.UnixUserPassword, LDAPProperties.MsSFU30Password,
            LDAPProperties.UnicodePassword, LDAPProperties.ProfilePath, LDAPProperties.ScriptPath,
            LDAPProperties.ExpirePasswordsOnSmartCardOnlyAccounts, LDAPProperties.MachineAccountQuota, 
            LDAPProperties.SupportedEncryptionTypes, LDAPProperties.DSHeuristics,
            LDAPProperties.MinPwdLength, LDAPProperties.PwdProperties, LDAPProperties.MinPwdAge, 
            LDAPProperties.MaxPwdAge, LDAPProperties.PwdHistoryLength, LDAPProperties.LockoutDuration, 
            LDAPProperties.LockoutThreshold, LDAPProperties.LockOutObservationWindow, LDAPProperties.GroupType, 
            LDAPProperties.PrincipalName
        };

        public static readonly string[] ContainerProps =
        {
            LDAPProperties.DisplayName, LDAPProperties.Name, LDAPProperties.ObjectGUID, LDAPProperties.GPLink,
            LDAPProperties.GroupPolicyOptions, LDAPProperties.ObjectClass
        };

        public static readonly string[] SPNTargetProps =
        {
            LDAPProperties.ServicePrincipalNames, LDAPProperties.SAMAccountName, LDAPProperties.SAMAccountType
        };

        public static readonly string[] DomainTrustProps =
        {
            LDAPProperties.TrustAttributes, LDAPProperties.SecurityIdentifier, LDAPProperties.TrustDirection,
            LDAPProperties.TrustType, LDAPProperties.CanonicalName
        };

        public static readonly string[] GPOLocalGroupProps =
        {
            LDAPProperties.GPLink, LDAPProperties.Name
        };

        public static readonly string[] CertAbuseProps =
        {
            LDAPProperties.CertificateTemplates, LDAPProperties.Flags, LDAPProperties.DNSHostName, LDAPProperties.CACertificate, LDAPProperties.PKINameFlag,
            LDAPProperties.PKIEnrollmentFlag, LDAPProperties.DisplayName, LDAPProperties.Name, LDAPProperties.TemplateSchemaVersion, LDAPProperties.CertTemplateOID,
            LDAPProperties.PKIOverlappedPeriod, LDAPProperties.PKIExpirationPeriod, LDAPProperties.ExtendedKeyUsage, LDAPProperties.NumSignaturesRequired,
            LDAPProperties.CertificateApplicationPolicy, LDAPProperties.CertificatePolicy, LDAPProperties.IssuancePolicies, LDAPProperties.CrossCertificatePair,
            LDAPProperties.ApplicationPolicies, LDAPProperties.PKIPrivateKeyFlag, LDAPProperties.OIDGroupLink
        };

        public static readonly string[] StealthProperties = {
            LDAPProperties.HomeDirectory, LDAPProperties.ScriptPath, LDAPProperties.ProfilePath
        };

        public static readonly string[] SiteProps =
        {
            LDAPProperties.DisplayName, LDAPProperties.Name, LDAPProperties.ObjectGUID, LDAPProperties.GPLink,
            LDAPProperties.GroupPolicyOptions, LDAPProperties.ObjectClass
        };

        public static readonly string[] SiteServerProps =
        {
            LDAPProperties.DisplayName, LDAPProperties.Name, LDAPProperties.ObjectGUID, LDAPProperties.ObjectClass, LDAPProperties.DNSHostName,
            LDAPProperties.ServerReference
        };

        public static readonly string[] SiteSubnetProps =
        {
            LDAPProperties.DisplayName, LDAPProperties.Name, LDAPProperties.CanonicalName, LDAPProperties.ObjectGUID, LDAPProperties.ObjectClass,
            LDAPProperties.SiteObject
        };
    }
}