using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.SMB.SMB2
{
    /// <summary>
    /// SMB2 Signing Algorithms
    /// </summary>
    public enum SMB2SigningAlgorithm : ushort
    {
        HmacSha256 = 0x0000,
        AesCmac = 0x0001,
        AesGmac = 0x0002
    }
}
