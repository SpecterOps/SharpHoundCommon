using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class StringArrayRegistryAPIResult : APIResult
    {
        public String[] Data { get; set; } = Array.Empty<String>();
    }
}