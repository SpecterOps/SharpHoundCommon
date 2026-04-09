using System;

namespace SharpHoundCommonLib.Exceptions
{
    public class NoLdapDataException : Exception
    {
        public int ErrorCode { get; set; }
        public NoLdapDataException(int errorCode)
        {
            ErrorCode = errorCode;
        }
    }
}