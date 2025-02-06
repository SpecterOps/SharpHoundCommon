using System;

namespace SharpHoundCommonLib.OutputTypes
{
    public class SessionAPIResult : APIResult.APIResult
    {
        public Session[] Results { get; set; } = Array.Empty<Session>();
    }
}