using SharpHoundCommonLib.OutputTypes.APIResult;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib.OutputTypes
{
    public class CARegistryData
    {
        public APIResult<ACE[]> CASecurity { get; set; }
        public APIResult<EnrollmentAgentRestriction[]> EnrollmentAgentRestrictions { get; set; }
        public APIResult<bool> IsUserSpecifiesSanEnabled { get; set; }
        public APIResult<bool> RoleSeparationEnabled { get; set; }
    }
}