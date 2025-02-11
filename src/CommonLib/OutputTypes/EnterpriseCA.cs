namespace SharpHoundCommonLib.OutputTypes
{
    public class EnterpriseCA : OutputBase
    {
        public string HostingComputer { get; set; }
        public CARegistryData CARegistryData { get; set; }
        public TypedPrincipal[] EnabledCertTemplates { get; set; }
        public APIResult<CAEnrollmentEndpoint[]> HttpEnrollmentEndpoints { get; set; }
    }
}