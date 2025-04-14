using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class CAEnrollmentProcessorTest : IDisposable {

        private readonly ITestOutputHelper _testOutputHelper;

        public CAEnrollmentProcessorTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }
    
        // TODO: Has error "The requested security protocol is not supported
        // [Theory]
        // [MemberData(nameof(BuildEnrollmentUrlsData))]
        // public async Task CAEnrollmentProcessor_BuildEnrollmentUrls(CAEnrollmentEndpointType type, Uri expectedhttpUrl, Uri expectedhttpsUrl)
        // {
        //     var processor = new CAEnrollmentProcessor("primary.testlab.local", "primary-dc-ca");
        //     (Uri httpUrl, Uri httpsUrl) = processor.BuildEnrollmentUrls(type);
        //
        //     Assert.Equal(httpUrl, expectedhttpUrl);
        //     Assert.Equal(httpsUrl, expectedhttpsUrl);
        // }
        //
        // public static IEnumerable<object[]> BuildEnrollmentUrlsData =>
        //     new List<object[]>
        //     {
        //         new object[]
        //         {
        //             CAEnrollmentEndpointType.WebEnrollmentApplication,
        //             new Uri("http://primary.testlab.local/certsrv/"),
        //             new Uri("https://primary.testlab.local/certsrv/")
        //         },
        //         new object[]
        //         {
        //             CAEnrollmentEndpointType.EnrollmentWebService,
        //             new Uri("http://primary.testlab.local/primary-dc-ca_CES_Kerberos/service.svc"),
        //             new Uri("https://primary.testlab.local/primary-dc-ca_CES_Kerberos/service.svc")
        //         }
        //     };
    }
}