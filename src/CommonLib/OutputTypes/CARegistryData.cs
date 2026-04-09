namespace SharpHoundCommonLib.OutputTypes
{
    public class CARegistryData
    {
        public AceRegistryAPIResult CASecurity { get; set; }
        public EnrollmentAgentRegistryAPIResult EnrollmentAgentRestrictions { get; set; }
        public BoolRegistryAPIResult IsUserSpecifiesSanEnabled { get; set; }
        public BoolRegistryAPIResult RoleSeparationEnabled { get; set; }
    }
}