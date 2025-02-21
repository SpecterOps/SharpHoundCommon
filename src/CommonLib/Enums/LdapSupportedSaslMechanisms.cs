using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Enums {
    public static class LdapSupportedSaslMechanisms {
        public const string GSSAPI = "GSSAPI";
        public const string GSS_SPNEGO = "GSS-SPNEGO";
        public const string EXTERNAL = "EXTERNAL";
        public const string DIGEST_MD5 = "DIGEST_MD5";
    }
}