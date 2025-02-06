using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class AceRegistryAPIResult : APIResult.APIResult
    {
        public ACE[] Data { get; set; } = Array.Empty<ACE>();
    }
}