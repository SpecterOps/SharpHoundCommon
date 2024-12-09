using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Ntlm;
using SharpHoundCommonLib.OutputTypes;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors
{
    public class CAEnrollmentProcessor
    {
        private readonly string _caDnsHostname;
        private readonly string _caName;
        private readonly ILogger _logger;
        private readonly IHttpClientFactory _httpClientFactory;

        public CAEnrollmentProcessor(string caDnsHostname, string caName, ILogger log = null)
        {
            ServicePointManager.SecurityProtocol |=
                SecurityProtocolType.Ssl3
                | SecurityProtocolType.Tls12
                | SecurityProtocolType.Tls11
                | SecurityProtocolType.Tls;

            _caDnsHostname = caDnsHostname;
            _caName = caName;
            _logger = log ?? Logging.LogProvider.CreateLogger("CAEnrollmentProcessor");

            _httpClientFactory = new HttpClientFactory();
        }


        public async Task<IEnumerable<ApiResult<CAEnrollmentEndpoint>>> ScanAsync()
        {
            var endpoints = new List<ApiResult<CAEnrollmentEndpoint>>();

            try
            {
                var webEnrollmentTask = ScanHttpEndpoint(CAEnrollmentEndpointType.WebEnrollmentApplication);
                var webServiceTask = ScanHttpEndpoint(CAEnrollmentEndpointType.EnrollmentWebService);
                // var rpcServiceTask = CheckEnrollmentRpcAsync();
                // var dcomServiceTask = CheckEnrollmentDcomAsync();

                await Task.WhenAll(
                    webEnrollmentTask,
                    webServiceTask
                    //rpcServiceTask,
                    //dcomServiceTask,
                );

                endpoints.AddRange(await webEnrollmentTask);
                endpoints.AddRange(await webServiceTask);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while scanning enrollment endpoints");
            }

            return endpoints;
        }

        private async Task<IEnumerable<ApiResult<CAEnrollmentEndpoint>>> ScanHttpEndpoint(CAEnrollmentEndpointType type)
        {
            var endpoints = new List<ApiResult<CAEnrollmentEndpoint>>();
            var (httpUrl, httpsUrl) = BuildEnrollmentUrls(type);


            // Check 1 - ESC8 via HTTP
            // Is the HTTP URL accessible via NTLM? If so, it's vulnerable to NTLM relay
            var endpoint = await GetNtlmEndpoint(httpUrl, null, type, CAEnrollmentEndpointScanResult.Vulnerable_NtlmHttpEndpoint);
            endpoints.Add(endpoint);

            // Check 2 - ESC8 via HTTPS w/o channel binding (EPA)
            // Is the HTTPS URL accessible via NTLM with bad channel bindings? (i.e. channel binding is not enforced)
            var esc8Https = await GetNtlmEndpoint(
                httpsUrl,
                useBadChannelBinding: true,
                type,
                CAEnrollmentEndpointScanResult.Vulnerable_NtlmHttpsNoChannelBinding
            );
            endpoints.Add(esc8Https);

            // TODO: For completeness/awareness, check if the endpoint is accessible via NTLM with valid Channel Bindings?

            return endpoints;
        }

        private (Uri httpUrl, Uri httpsUrl) BuildEnrollmentUrls(CAEnrollmentEndpointType type)
        {
            switch (type)
            {
                case CAEnrollmentEndpointType.WebEnrollmentApplication:
                    return (new Uri($"http://{_caDnsHostname}/certsrv/"),
                            new Uri($"https://{_caDnsHostname}/certsrv/"));

                case CAEnrollmentEndpointType.EnrollmentWebService:
                    return (new Uri($"http://{_caDnsHostname}/{_caName}_CES_Kerberos/service.svc"),
                            new Uri($"https://{_caDnsHostname}/{_caName}_CES_Kerberos/service.svc"));

                default:
                    throw new ArgumentException("Unhandled enrollment endpoint type");
            }
        }


        private async Task<ApiResult<CAEnrollmentEndpoint>> GetNtlmEndpoint(Uri url, bool? useBadChannelBinding, CAEnrollmentEndpointType type, CAEnrollmentEndpointScanResult scanResult)
        {
            var authService = new HttpNtlmAuthenticationService(
                    _logger,
                    new HttpClientFactory()
                )
            {
                Url = url
            };

            var output = new CAEnrollmentEndpoint(url, type, scanResult);

            try
            {
                await authService.EnsureRequiresAuth(false, useBadChannelBinding);
                return ApiResult<CAEnrollmentEndpoint>.CreateSuccess(output);
            }
            catch (HttpRequestException ex)
            {
                if (ex.InnerException is WebException)
                {
                    var webEx = (WebException)ex.InnerException;


                    if (webEx.InnerException is SocketException)
                    {
                        output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PortInaccessible;
                        return ApiResult<CAEnrollmentEndpoint>.CreateSuccess(output);
                    }
                    else if (webEx.Status == WebExceptionStatus.NameResolutionFailure)
                    {
                        return ApiResult<CAEnrollmentEndpoint>.CreateError("Could not resolve hostname");
                    }
                    else if (webEx.Response is HttpWebResponse httpResponse)
                    {
                        HttpStatusCode statusCode = httpResponse.StatusCode;

                        switch (statusCode)
                        {
                            case HttpStatusCode.NotFound:
                                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathNotFound;
                                break;
                            case HttpStatusCode.Forbidden:
                                // Returned if the IIS is configured to require SSL (so no HTTP possible)
                                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathForbidden;
                                break;
                            default:
                                return ApiResult<CAEnrollmentEndpoint>
                                    .CreateError($"Unexpected status code '{statusCode}' for the URL {url}. UseBadChannelBindings: {useBadChannelBinding}");
                        }

                        return ApiResult<CAEnrollmentEndpoint>.CreateSuccess(output);
                    }
                    else
                    {
                        Console.WriteLine($"WebException occurred: {ex}");
                    }

                    return ApiResult<CAEnrollmentEndpoint>
                        .CreateError($"Unhandled WebException. Url: {url}. Exception: {webEx}. Inner: {webEx.InnerException}  Data: {webEx.Data}");
                }
                else
                {
                    return ApiResult<CAEnrollmentEndpoint>
                            .CreateError($"HttpRequestException occured checking NTLM accessibility for URL: {url}. Exception: {ex}");
                }
            }
            catch (HttpUnauthorizedException ex)
            {
                if (useBadChannelBinding == true)
                {
                    output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_NtlmChannelBindingRequired;
                    return ApiResult<CAEnrollmentEndpoint>.CreateSuccess(output);
                }
                else
                {
                    return ApiResult<CAEnrollmentEndpoint>
                    .CreateError($"401 Unauthorized exception checking NTLM accessibility for URL: {url}. Exception: {ex}");
                }
            }
            catch(HttpForbiddenException)
            {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathForbidden;
                return ApiResult<CAEnrollmentEndpoint>
                    .CreateSuccess(output);
            }
            catch(HttpServerErrorException)
            {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathNotFound;
                return ApiResult<CAEnrollmentEndpoint>
                    .CreateSuccess(output);
            }
            catch (MissingChallengeException)
            {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_NoNtlmChallenge;
                return ApiResult<CAEnrollmentEndpoint>
                    .CreateSuccess(output);
            }
            catch (Exception ex)
            {
                return ApiResult<CAEnrollmentEndpoint>
                    .CreateError($"Unhandled exception checking NTLM accessibility for URL: {url}. BadChannelBindings: {useBadChannelBinding}.  Exception: {ex}");
            }
        }

        private async Task<bool> CanAccessUrlWithKerberosAsync(string url, bool useBadChannelBinding)
        {
            using (var client = _httpClientFactory.CreateAuthenticatedHttpClient(new Uri(url)))
            {
                try
                {
                    HttpResponseMessage response = await client.GetAsync(url);

                    return true;
                }
                catch (HttpRequestException e)
                {
                    Console.WriteLine($"Error: {e.Message}");

                    return false;
                }
            }
        }

    }

}
