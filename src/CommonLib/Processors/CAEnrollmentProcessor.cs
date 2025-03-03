using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Ntlm;
using SharpHoundCommonLib.OutputTypes;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors {
    /// <summary>
    /// This processor, given an Enrollment Certificate Authority, checks the HTTP endpoints for specific NTLM settings (http enablement, channel bindings)
    /// </summary>
    public class CAEnrollmentProcessor {
        private readonly string _caDnsHostname;
        private readonly string _caName;
        private readonly ILogger _logger;

        public CAEnrollmentProcessor(string caDnsHostname, string caName, ILogger log = null) {
            ServicePointManager.SecurityProtocol |=
                SecurityProtocolType.Ssl3
                | SecurityProtocolType.Tls12
                | SecurityProtocolType.Tls11
                | SecurityProtocolType.Tls;

            _caDnsHostname = caDnsHostname;
            _caName = caName;
            _logger = log ?? Logging.LogProvider.CreateLogger("CAEnrollmentProcessor");
        }


        public async Task<IEnumerable<APIResult<CAEnrollmentEndpoint>>> ScanAsync() {
            var endpoints = new List<APIResult<CAEnrollmentEndpoint>>();

            try {
                var webEnrollmentTask = ScanHttpEndpoint(CAEnrollmentEndpointType.WebEnrollmentApplication);
                var webServiceTask = ScanHttpEndpoint(CAEnrollmentEndpointType.EnrollmentWebService);

                await Task.WhenAll(
                    webEnrollmentTask,
                    webServiceTask
                );

                endpoints.AddRange(await webEnrollmentTask);
                endpoints.AddRange(await webServiceTask);
            } catch (Exception ex) {
                _logger.LogError(ex, "An error occurred while scanning enrollment endpoints");
            }

            return endpoints;
        }

        private async Task<IEnumerable<APIResult<CAEnrollmentEndpoint>>>
            ScanHttpEndpoint(CAEnrollmentEndpointType type) {
            var endpoints = new List<APIResult<CAEnrollmentEndpoint>>();
            var (httpUrl, httpsUrl) = BuildEnrollmentUrls(type);


            // Check 1 - ESC8 via HTTP
            // Is the HTTP URL accessible via NTLM? If so, it's vulnerable to NTLM relay
            var endpoint = await GetNtlmEndpoint(httpUrl, null, type,
                CAEnrollmentEndpointScanResult.Vulnerable_NtlmHttpEndpoint);
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
            return endpoints;
        }

        private (Uri httpUrl, Uri httpsUrl) BuildEnrollmentUrls(CAEnrollmentEndpointType type) {
            switch (type) {
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


        private async Task<APIResult<CAEnrollmentEndpoint>> GetNtlmEndpoint(Uri url, bool? useBadChannelBinding,
            CAEnrollmentEndpointType type, CAEnrollmentEndpointScanResult scanResult) {
            var authService = new HttpNtlmAuthenticationService(
                new HttpClientFactory()
            );

            var output = new CAEnrollmentEndpoint(url, type, scanResult);

            try {
                await authService.EnsureRequiresAuth(url, useBadChannelBinding);
                return APIResult<CAEnrollmentEndpoint>.Success(output);
            } catch (HttpRequestException ex) {
                if (ex.InnerException is WebException) {
                    var webEx = (WebException)ex.InnerException;


                    if (webEx.InnerException is SocketException) {
                        output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PortInaccessible;
                        return APIResult<CAEnrollmentEndpoint>.Success(output);
                    }

                    if (webEx.Status == WebExceptionStatus.NameResolutionFailure) {
                        return APIResult<CAEnrollmentEndpoint>.Failure("Could not resolve hostname");
                    }

                    if (webEx.Response is HttpWebResponse httpResponse) {
                        var statusCode = httpResponse.StatusCode;

                        switch (statusCode) {
                            case HttpStatusCode.NotFound:
                                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathNotFound;
                                break;
                            case HttpStatusCode.Forbidden:
                                // Returned if the IIS is configured to require SSL (so no HTTP possible)
                                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathForbidden;
                                break;
                            default:
                                return APIResult<CAEnrollmentEndpoint>
                                    .Failure(
                                        $"Unexpected status code '{statusCode}' for the URL {url}. UseBadChannelBindings: {useBadChannelBinding}");
                        }

                        return APIResult<CAEnrollmentEndpoint>.Success(output);
                    }

                    Console.WriteLine($"WebException occurred: {ex}");

                    return APIResult<CAEnrollmentEndpoint>
                        .Failure(
                            $"Unhandled WebException. Url: {url}. Exception: {webEx.Message}. Inner: {webEx.InnerException.Message}  Data: {webEx.Data}");
                }

                return APIResult<CAEnrollmentEndpoint>
                    .Failure(
                        $"HttpRequestException occured checking NTLM accessibility for URL: {url}. Exception: {ex.Message}");
            } catch (HttpUnauthorizedException ex) {
                if (useBadChannelBinding == true) {
                    output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_NtlmChannelBindingRequired;
                    return APIResult<CAEnrollmentEndpoint>.Success(output);
                }

                return APIResult<CAEnrollmentEndpoint>
                    .Failure(
                        $"401 Unauthorized exception checking NTLM accessibility for URL: {url}. Exception: {ex.Message}");
            } catch (HttpForbiddenException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathForbidden;
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (HttpServerErrorException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathNotFound;
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (MissingChallengeException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_NoNtlmChallenge;
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (ExtendedProtectionMisconfiguredException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_EpaMisconfigured;
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (Exception ex) {
                return APIResult<CAEnrollmentEndpoint>
                    .Failure(
                        $"Unhandled exception checking NTLM accessibility for URL: {url}. BadChannelBindings: {useBadChannelBinding}.  Exception: {ex.Message}");
            }
        }
    }
}