using System.Collections.Generic;
using System.Security.Principal;
using CommonLibTest.Facades;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest
{
    public class SearchResultEntryTests
    {
        [WindowsOnlyFact]
        public void Test_GetLabelIssuanceOIDObjects()
        {
            var sid = new SecurityIdentifier("S-1-5-21-3130019616-2776909439-2417379446-500");
            var bsid = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bsid, 0);
            var attribs = new Dictionary<string, object>
            {
                { "objectsid", bsid},
                { "objectclass", "msPKI-Enterprise-Oid" },
                { "flags", "2" }
            };

            var sre = MockableSearchResultEntry.Construct(attribs, "CN=Test,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration");
            Assert.Equal(Label.IssuancePolicy, sre.GetLabel());

            sre = MockableSearchResultEntry.Construct(attribs, "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration");
            Assert.Equal(Label.Container, sre.GetLabel());
        }
    }
}