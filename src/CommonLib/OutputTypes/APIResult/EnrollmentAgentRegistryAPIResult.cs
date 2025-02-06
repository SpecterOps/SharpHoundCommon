using System;
using SharpHoundCommonLib.Processors;

namespace SharpHoundCommonLib.OutputTypes
{
    public class EnrollmentAgentRegistryAPIResult : APIResult.APIResult
    {
        public EnrollmentAgentRestriction[] Restrictions { get; set; } = Array.Empty<EnrollmentAgentRestriction>();
    }
}