using System;
using System.Text;
using System.Threading.Tasks;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Enums;
using Xunit;

namespace CommonLibTest {
    public class CommonLibHelperTest {
        [Fact]
        public void RemoveDistinguishedNamePrefix_ExpectedResult() {
            var dn = "CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM";
            var result = Helpers.RemoveDistinguishedNamePrefix(dn);
            Assert.Equal("OU=Sales,DC=Fabrikam,DC=COM", result);
            result = Helpers.RemoveDistinguishedNamePrefix(
                "CN=Administrator,CN=Users,DC=testlab,DC=local");
            Assert.Equal("CN=Users,DC=testlab,DC=local", result);
            result = Helpers.RemoveDistinguishedNamePrefix(
                "CN=Litware,OU=Docs\\, Adatum,DC=Fabrikam,DC=COM");
            Assert.Equal("OU=Docs\\, Adatum,DC=Fabrikam,DC=COM", result);
            result = Helpers.RemoveDistinguishedNamePrefix(
                "OU=Test\\, OU,OU=Test,DC=Fabrikam,DC=COM");
            Assert.Equal("OU=Test,DC=Fabrikam,DC=COM", result);
        }

        [Fact]
        public void SplitGPLinkProperty_ValidPropFilterEnabled_ExpectedResult() {
            var isPropFilterEnabled = false;
            //TODO: Ari, proper test string?
            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; SIP:foouser@example.co.uk; smtp:foouser@sub1.example.co.uk; smtp:foouser@sub2.example.co.uk; SMTP:foouser@example.co.uk][]";

            var res = Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);

            foreach (var parsedGPLink in res)
                Assert.Equal("cn=foouser (blah)123", parsedGPLink.DistinguishedName);
            // TODO: issue here with test data? Assert.Equal("1", parsedGPLink.Status);
        }

        [Fact]
        public void SplitGPLinkProperty_ValidPropFilterDisabled_ExpectedResult() {
            var isPropFilterEnabled = false;
            //TODO: Ari, proper test string?
            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; SIP:foouser@example.co.uk; smtp:foouser@sub1.example.co.uk; smtp:foouser@sub2.example.co.uk; SMTP:foouser@example.co.uk][]";

            var res = Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);

            foreach (var parsedGPLink in res)
                Assert.Equal("cn=foouser (blah)123", parsedGPLink.DistinguishedName);
            // TODO: issue here with test data? Assert.Equal("1", parsedGPLink.Status);
        }

        /// 
        [Fact]
        public void SplitGPLinkProperty_PropWithUnsupportedDelimiter_FilterEnabled_ExpectedResult() {
            var isPropFilterEnabled = true;
            //TODO: Ari, proper test string?
            var testGPLinkProperty =
                "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; DC=somedomainName; SIP:foouser@example.co.uk; smtp:foouser@sub1.example.co.uk; smtp:foouser@sub2.example.co.uk; SMTP:foouser@example.co.uk][]";

            var res = Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);

            foreach (var parsedGPLink in res)
                Assert.Equal("cn=foouser (blah)123", parsedGPLink.DistinguishedName);
            // TODO: issue here with test data? Assert.Equal("1", parsedGPLink.Status);
        }

        [Fact]
        public void SplitGPLinkProperty_InValidPropFilterDisabled_ExpectedResult() {
            var isPropFilterEnabled = false;
            //TODO: Ari, proper test string?
            var testGPLinkProperty = "/*obviously wrong data*/";
            var res = Helpers.SplitGPLinkProperty(testGPLinkProperty, isPropFilterEnabled);
            Assert.Empty(res);
        }

        [Fact]
        public void SamAccountTypeToType_ValidString_CorrectLabel() {
            var accountTypeLookup = new (string accountType, Label label)[] {
                (accountType: "268435456", label: Label.Group),
                (accountType: "268435457", label: Label.Group),
                (accountType: "536870912", label: Label.Group),
                (accountType: "536870913", label: Label.Group),
                (accountType: "805306369", Label.Computer),
                (accountType: "805306368", Label.User),
                (accountType: "805306370", Label.User)
            };

            foreach (var e in accountTypeLookup) {
                var result = Helpers.SamAccountTypeToType(e.accountType);
                Assert.Equal(result, e.label);
            }
        }

        [Fact]
        public void SamAccountTypeToType_InValidString_CorrectLabel() {
            var result = Helpers.SamAccountTypeToType("nonsense_^&^^&(*^*^*&(&^&(^*AAAA");
            Assert.Equal(Label.Base, result);
        }

        // [Fact]
        // public void ConvertSidToHexSid_ValidString_ValidHex()
        // {
        //     var hexString = SharpHoundCommonLib.Helpers.ConvertSidToHexSid("268435457");
        //     var securityIdentifier = new SecurityIdentifier("268435457");
        //     var sidBytes = new byte[securityIdentifier.BinaryLength];
        //     securityIdentifier.GetBinaryForm(sidBytes, 0);

        //     var output = $"\\{BitConverter.ToString(sidBytes).Replace('-', '\\')}";
        //     Assert.Equal(output, hexString);
        // }

        [Fact]
        public void ConvertGuidToHexGuid_ValidStringGuid_ValidHex() {
            // Atmoic conversion test. Add as many variants as needed to increase confidence.

            var guid = Guid.NewGuid();
            var hexString = Helpers.ConvertGuidToHexGuid(guid.ToString());

            // We recreate part of thr operation here to test parity. If you the function under test changes this code then the test may fail and indicate drift in the code away from expected behavior.
            var output = $"\\{BitConverter.ToString(guid.ToByteArray()).Replace('-', '\\')}";
            Assert.Equal(output, hexString);
        }

        [Fact]
        public void DistinguishedNameToDomain_ValidDistinguishedName_ExpectedDomainValue() {
            var expected = "FABRIKAM.COM";
            var actual =
                Helpers.DistinguishedNameToDomain("CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM");
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void DistinguishedNameToDomain_InValidDistinguishedName_ReturnsNull() {
            var testDCQuery = "[LDAP:/o=foo/ou=foo Group (ABC123)/cn=foouser (blah)123; DX=wjatvar][]";
            var actual = Helpers.DistinguishedNameToDomain(testDCQuery);
            Assert.Null(actual);
        }

        [Fact]
        public void StripServicePrincipalName_ValidServicePrincipal_ExpectedHostName() {
            var testString = "www/WEB-SERVER-01.adsec.local";
            var expected = "WEB-SERVER-01.adsec.local";
            var actual = Helpers.StripServicePrincipalName(testString);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void StripServicePrincipalName_InValidServicePrincipal_ExpectedHostName() {
            var testString = "234234f___bb4::fadfs";
            var expected = "234234f___bb4::fadfs";
            var actual = Helpers.StripServicePrincipalName(testString);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void StripServicePrincipalName_EmptyHost_Valid() {
            var testString = "MSSQLSvc/:1433";
            var expected = "";
            var actual = Helpers.StripServicePrincipalName(testString);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void B64ToBytes_String_ValidBase64String() {
            var testString = "obviously nonsense";
            var exampleBytes = Encoding.UTF8.GetBytes(testString);
            var compareString = Convert.ToBase64String(exampleBytes);
            var result = Helpers.Base64(testString);
            Assert.Equal(compareString, result);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_ValidFileTime_ValidUnixEpoch() {
            var testFileTime = "132260149842749745";
            var result = Helpers.ConvertFileTimeToUnixEpoch(testFileTime);
            var expected = 1581541384;
            Assert.Equal(expected, result);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_Null_NegativeOne() {
            var result = Helpers.ConvertFileTimeToUnixEpoch(null);
            Assert.Equal(-1, result);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_WrongFormat_FortmatException() {
            Exception ex =
                Assert.Throws<FormatException>(() => Helpers.ConvertFileTimeToUnixEpoch("asdsf"));
            Assert.Equal("The input string 'asdsf' was not in a correct format.", ex.Message);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_BadInput_CastExceptionReturnsNegativeOne() {
            var result = Helpers.ConvertFileTimeToUnixEpoch("-3242432");
            Assert.Equal(-1, result);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_ValidTimestamp_ValidUnixEpoch() {
            var d = DateTime.Parse("2021-06-21T00:00:00");
            var result =
                Helpers.ConvertFileTimeToUnixEpoch(d.ToFileTimeUtc().ToString()); // get the epoch
            var dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(result); // create an offset from the epoch
            var testDate = dateTimeOffset.UtcDateTime;

            Assert.Equal(d.ToUniversalTime().Date, testDate);
        }

        [Fact]
        public void ConvertFileTimeToUnixEpoch_InvalidTimestamp_FormatException() {
            Exception ex = Assert.Throws<FormatException>(() =>
                Helpers.ConvertFileTimeToUnixEpoch("-201adsfasf12180244"));
            Assert.Equal("The input string '-201adsfasf12180244' was not in a correct format.", ex.Message);
        }

        [Fact]
        public void DistinguishedNameToDomain_RegularObject_CorrectDomain() {
            var result = Helpers.DistinguishedNameToDomain(
                "CN=Account Operators,CN=Builtin,DC=testlab,DC=local");
            Assert.Equal("TESTLAB.LOCAL", result);

            result = Helpers.DistinguishedNameToDomain("DC=testlab,DC=local");
            Assert.Equal("TESTLAB.LOCAL", result);
        }

        [Fact]
        public void DistinguishedNameToDomain_DeletedObjects_CorrectDomain() {
            var result = Helpers.DistinguishedNameToDomain(
                @"DC=..Deleted-_msdcs.testlab.local\0ADEL:af1f072f-28d7-4b86-9b87-a408bfc9cb0d,CN=Deleted Objects,DC=testlab,DC=local");
            Assert.Equal("TESTLAB.LOCAL", result);
        }

        [Fact]
        public void ConvertTimestampToUnixEpoch_ValidTimestamp() {
            var d = DateTime.Parse("2025-04-07T00:00:00.0000000-07:00");
            var result =
                Helpers.ConvertTimestampToUnixEpoch(d.ToString("yyyyMMddHHmmss.0K"));
            var dateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(result);

            Assert.Equal(d.ToUniversalTime(), dateTimeOffset.DateTime);
        }

        [Fact]
        public void ConvertTimestampToUnixEpoch_InvalidTimestamp() {
            var result =
                Helpers.ConvertTimestampToUnixEpoch("-201adsfasf12180244");

            Assert.Equal(0, result);
        }

        [Fact]
        public void RetryOnException_ThrowsExpected() {
            int attemptCount = 0;
            Func<Task> throws = () => {
                attemptCount++;
                throw new ApplicationException();
            };

            Assert.ThrowsAsync<ApplicationException>(async () => await Helpers.RetryOnException<ApplicationException>(throws, 3));
            Assert.Equal(3, attemptCount);
        }

        [Fact]
        public void RetryOnException_ThrowsUnexpected() {
            int attemptCount = 0;
            Func<Task> throws = () => {
                attemptCount++;
                throw new Exception();
            };

            Assert.ThrowsAsync<Exception>(async () => await Helpers.RetryOnException<ApplicationException>(throws, 3));
            // First try throws an Exception, but retry only happens on ApplicationException
            Assert.Equal(1, attemptCount);
        }

        [Fact]
        public async Task RetryOnException_SucceedsOnLastAttempt() {
            int attemptCount = 0;
            bool success = false;
            Func<Task> throws = () => {
                attemptCount++;
                if (attemptCount < 3)
                    throw new ApplicationException();

                success = true;
                return Task.CompletedTask;
            };

            await Helpers.RetryOnException<ApplicationException>(throws, 3);

            Assert.True(success);
        }
    }
}