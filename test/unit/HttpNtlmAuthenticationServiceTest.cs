using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using SharpHoundCommonLib.Ntlm;
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
        public void HttpNtlmAuthenticationService_ExtractAuthSchemes_AuthNotRequiredException() {
            var service = new HttpNtlmAuthenticationService(new NtlmHttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage {
                StatusCode = HttpStatusCode.OK,
            };

            var ex = Assert.Throws<AuthNotRequiredException>(() => service.ExtractAuthSchemes(httpResponseMessage));

            Assert.Equal("Authorization was not solicited when enumerating Authentication schemes", ex.Message);
        }

        [Fact]
        public void HttpNtlmAuthenticationService_ExtractAuthSchemes_HttpForbiddenException() {
            var service = new HttpNtlmAuthenticationService(new NtlmHttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage {
                StatusCode = HttpStatusCode.Forbidden,
            };

            var ex = Assert.Throws<HttpForbiddenException>(() => service.ExtractAuthSchemes(httpResponseMessage));

            Assert.Equal("Forbidden when enumerating Auth schemes", ex.Message);
        }

        [Fact]
        public void HttpNtlmAuthenticationService_ExtractAuthSchemes_HttpServerErrorException() {
            var service = new HttpNtlmAuthenticationService(new NtlmHttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage {
                StatusCode = HttpStatusCode.InternalServerError,
            };

            var ex = Assert.Throws<HttpServerErrorException>(() => service.ExtractAuthSchemes(httpResponseMessage));

            Assert.Equal("Server Error when enumerating Auth schemes", ex.Message);
        }

        [Fact]
        public void HttpNtlmAuthenticationService_ExtractAuthSchemes_Success() {
            var service = new HttpNtlmAuthenticationService(new NtlmHttpClientFactory(), null);
            var httpResponseMessage = new HttpResponseMessage();
            httpResponseMessage.StatusCode = HttpStatusCode.Accepted;
            httpResponseMessage.Headers.WwwAuthenticate.Add(
                new AuthenticationHeaderValue("NTLM", "realm=localhost"));
            httpResponseMessage.Headers.WwwAuthenticate.Add(
                new AuthenticationHeaderValue("Negotiate", "realm=localhost"));
            httpResponseMessage.Headers.WwwAuthenticate.Add(
                new AuthenticationHeaderValue("Basic", "realm=localhost"));

            var result = service.ExtractAuthSchemes(httpResponseMessage);

            Assert.Equal("NTLM", result[0]);
            Assert.Equal("Negotiate", result[1]);
        }

        // Obsolete by AdaptiveTimeout
        // [Fact]
        // public void HttpNtlmAuthenticationService_EnsureRequiresAuth_GetSupportedNtlmAuthSchemesAsync_Timeout() {
        //     var url = new Uri("http://primary.testlab.local/");
        //     var service = new HttpNtlmAuthenticationService(new HttpClientFactory(), null);
        //     var ex = Assert.ThrowsAsync<TimeoutException>(() =>
        //         service.EnsureRequiresAuth(url, true));
        //     Assert.Equal($"Timeout getting supported NTLM auth schemes for {url}", ex.Result.Message);

        // }

        // Obsolete by AdaptiveTimeout
        // [Fact]
        // public void HttpNtlmAuthenticationService_AuthWithBadChannelBindingsAsync_Timeout() {
        //     var url = new Uri("http://primary.testlab.local/");
        //     var authScheme = "NTLM";
        //     var service = new HttpNtlmAuthenticationService(new HttpClientFactory(), null);
        //     var httpResponseMessage = new HttpResponseMessage {
        //         StatusCode = HttpStatusCode.InternalServerError,
        //     };
        //     var mockAuthenticator = new Mock<NtlmAuthenticationHandler>(It.IsAny<string>(), null);
        //     mockAuthenticator.Setup(x =>
        //         x.PerformNtlmAuthenticationAsync(It.IsAny<INtlmTransport>(), It.IsAny<CancellationToken>())).Returns(async () => {
        //             await Task.Delay(1000);
        //             return httpResponseMessage;
        //         });

        //     var ex = Assert.ThrowsAsync<TimeoutException>(async () => await TestPrivateMethod.InstanceMethod<Task>(service,
        //         "AuthWithBadChannelBindingsAsync",
        //         [
        //             url, authScheme, TimeSpan.FromMilliseconds(1), mockAuthenticator.Object
        //         ]));
        //     Assert.Equal($"Timeout during NTLM authentication for {url} with {authScheme}", ex.Result.Message);

        // }

        //// Throws "no such host is known" exception
        // [Fact]
        // public void HttpNtlmAuthenticationService_AuthWithChannelBindingAsync_Timeout() {
        //     var url = new Uri("http://primary.testlab.local/");
        //     var authScheme = "NTLM";
        //     var service = new HttpNtlmAuthenticationService(new HttpClientFactory(), null);
        //     var ex = Assert.ThrowsAsync<TimeoutException>(async () => await TestPrivateMethod.InstanceMethod<Task>(service,
        //         "AuthWithChannelBindingAsync",
        //         [
        //             url, authScheme, TimeSpan.FromMilliseconds(1)
        //         ]));
        //     Assert.Equal($"Timeout during channel binding authentication for {url} with {authScheme}", ex.Result.Message);

        // }
    }
}