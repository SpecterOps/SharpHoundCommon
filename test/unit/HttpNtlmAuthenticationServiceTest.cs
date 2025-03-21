using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib;
using SharpHoundCommonLib.Ntlm;
using SharpHoundCommonLib.OutputTypes;
using SharpHoundCommonLib.Processors;
using SharpHoundRPC;
using Xunit;
using Xunit.Abstractions;

namespace CommonLibTest {
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
    public class HttpNtlmAuthenticationServiceTest : IDisposable {

        private readonly ITestOutputHelper _testOutputHelper;

        public HttpNtlmAuthenticationServiceTest(ITestOutputHelper testOutputHelper) {
            _testOutputHelper = testOutputHelper;
        }

        public void Dispose() {
        }
    
        [Fact]
        public async Task HttpNtlmAuthenticationService_ExtractAuthSchemes_AuthNotRequiredException()
        {
            var service = new HttpNtlmAuthenticationService(new HttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
            };

            var ex = Assert.Throws<AuthNotRequiredException>(() => service.ExtractAuthSchemes(httpResponseMessage));

            Assert.Equal(ex.Message, "Authorization was not solicited when enumerating Authentication schemes");
        }
        
        [Fact]
        public async Task HttpNtlmAuthenticationService_ExtractAuthSchemes_HttpForbiddenException()
        {
            var service = new HttpNtlmAuthenticationService(new HttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.Forbidden,
            };

            var ex = Assert.Throws<HttpForbiddenException>(() => service.ExtractAuthSchemes(httpResponseMessage));

            Assert.Equal(ex.Message, "Forbidden when enumerating Auth schemes");
        }
        
        [Fact]
        public async Task HttpNtlmAuthenticationService_ExtractAuthSchemes_HttpServerErrorException()
        {
            var service = new HttpNtlmAuthenticationService(new HttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.InternalServerError,
            };

            var ex = Assert.Throws<HttpServerErrorException>(() => service.ExtractAuthSchemes(httpResponseMessage));

            Assert.Equal(ex.Message, "Server Error when enumerating Auth schemes");
        }
        
        [Fact]
        public async Task HttpNtlmAuthenticationService_ExtractAuthSchemes_Success()
        {
            var service = new HttpNtlmAuthenticationService(new HttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage();
            httpResponseMessage.StatusCode = HttpStatusCode.Accepted;
            httpResponseMessage.Headers.WwwAuthenticate.Add(
                new AuthenticationHeaderValue("NTLM", "realm=localhost"));
            httpResponseMessage.Headers.WwwAuthenticate.Add(
                new AuthenticationHeaderValue("Negotiate", "realm=localhost"));
            httpResponseMessage.Headers.WwwAuthenticate.Add(
                new AuthenticationHeaderValue("Basic", "realm=localhost"));

            var result = service.ExtractAuthSchemes(httpResponseMessage);

            Assert.Equal(result[0], "NTLM");
            Assert.Equal(result[1], "Negotiate");
        }
    }
}