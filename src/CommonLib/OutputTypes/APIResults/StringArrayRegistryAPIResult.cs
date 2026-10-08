using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class StringArrayRegistryAPIResult : APIResult
    {
        public string[] Data { get; set; } = [];
    }
}