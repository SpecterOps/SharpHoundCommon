using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.Ntlm;
using SharpHoundCommonLib.OutputTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.Processors {
    /// <summary>
    /// This processor, given an Enrollment Certificate Authority, checks the HTTP endpoints for specific NTLM settings (http enablement, channel bindings)
    /// </summary>
    public class CAEnrollmentProcessor {
        private readonly string _caDnsHostname;
        private readonly string _caName;
        private readonly ILogger _logger;

        private const SslProtocols CaEnrollmentSslProtocols = 
            SslProtocols.Ssl3 | SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12;

        public CAEnrollmentProcessor(string caDnsHostname, string caName, ILogger log = null) {
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
            
            endpoints = TagEndpoints(endpoints).ToList();

            return endpoints;
        }

        private IEnumerable<APIResult<CAEnrollmentEndpoint>> TagEndpoints(IEnumerable<APIResult<CAEnrollmentEndpoint>> endpoints) {
            var tagEndpoints = endpoints as APIResult<CAEnrollmentEndpoint>[] ?? endpoints.ToArray();
            foreach (var endpoint in tagEndpoints) {
                if (!endpoint.Collected)
                    continue;
                
                var enrollmentEndpoint = endpoint.Result;
                if (enrollmentEndpoint.Url.Scheme != Uri.UriSchemeHttps) {
                    switch (enrollmentEndpoint.Status) {
                        case CAEnrollmentEndpointScanResult.Vulnerable_NtlmHttpEndpoint:
                            endpoint.Result.ADCSWebEnrollmentHTTP = true;
                            break;
                    }
                } else {
                    switch (enrollmentEndpoint.Status) {
                        case CAEnrollmentEndpointScanResult.Vulnerable_NtlmHttpsNoChannelBinding:
                            endpoint.Result.ADCSWebEnrollmentHTTPS = true;
                            break;
                        case CAEnrollmentEndpointScanResult.NotVulnerable_NtlmChannelBindingRequired:
                            endpoint.Result.ADCSWebEnrollmentHTTPS = true;
                            endpoint.Result.ADCSWebEnrollmentEPA = true;
                            break;
                    }
                }
            }

            return tagEndpoints;
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

        internal (Uri httpUrl, Uri httpsUrl) BuildEnrollmentUrls(CAEnrollmentEndpointType type) {
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
                new NtlmHttpClientFactory(CaEnrollmentSslProtocols)
            );

            var output = new CAEnrollmentEndpoint(url, type, scanResult);

            try {
                await authService.EnsureRequiresAuth(url, useBadChannelBinding);
                _logger.LogDebug("{Url} was accessible. BadChannelBindings: {UseBadChannelBindings}. EndpointType {EndpointType}",
                    url.AbsoluteUri, useBadChannelBinding, type);
                return APIResult<CAEnrollmentEndpoint>.Success(output);
            } catch (HttpRequestException ex) {
                if (ex.InnerException is WebException webEx) {
                    if (webEx.InnerException is SocketException) {
                        output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PortInaccessible;
                        _logger.LogDebug("{Url} labeled not vulnerable due to port being inaccessible. EndpointType: {EndpointType}",
                            url.AbsoluteUri, type);
                        return APIResult<CAEnrollmentEndpoint>.Success(output);
                    }

                    if (webEx.Status == WebExceptionStatus.NameResolutionFailure) {
                        _logger.LogDebug("{Url} could not be resolved. BadChannelBindings: {UseBadChannelBindings}. EndpointType: {EndpointType}",
                            url.AbsoluteUri, useBadChannelBinding, type);
                        return APIResult<CAEnrollmentEndpoint>.Failure("Could not resolve hostname");
                    }

                    if (webEx.Response is HttpWebResponse httpResponse) {
                        var statusCode = httpResponse.StatusCode;

                        switch (statusCode) {
                            case HttpStatusCode.NotFound:
                                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathNotFound;
                                _logger.LogDebug("Path not found for {Url}; marking not vulnerable. BadChannelBindings: {UseBadChannelBindings}. EndpointType: {EndpointType}",
                                    url.AbsoluteUri, useBadChannelBinding, type);
                                break;
                            case HttpStatusCode.Forbidden:
                                // Returned if the IIS is configured to require SSL (so no HTTP possible)
                                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathForbidden;
                                _logger.LogDebug("Path forbidden for {Url}; marking not vulnerable. BadChannelBindings: {UseBadChannelBindings}. EndpointType: {EndpointType}",
                                    url.AbsoluteUri, useBadChannelBinding, type);
                                break;
                            default:
                                _logger.LogError("Unexpected status code while checking {Url}. StatusCode {StatusCode}. UseBadChannelBindings: {UseBadChannelBindings}, EndpointType: {EndpointType}",
                                    url.AbsoluteUri, statusCode, useBadChannelBinding, type);
                                return APIResult<CAEnrollmentEndpoint>
                                    .Failure(
                                        $"Unexpected status code '{statusCode}' for the URL {url}. UseBadChannelBindings: {useBadChannelBinding}");
                        }

                        return APIResult<CAEnrollmentEndpoint>.Success(output);
                    }

                    _logger.LogError(webEx, "Unhandled WebException while checking {Url}. Exception: {ExceptionMessage}. Inner: {InnerExceptionMessage}  Data: {ExceptionData}",
                        url.AbsoluteUri, webEx.Message, webEx.InnerException?.Message, webEx.Data);
                    return APIResult<CAEnrollmentEndpoint>
                        .Failure(
                            $"Unhandled WebException. Url: {url}. Exception: {webEx.Message}. Inner: {webEx.InnerException?.Message}  Data: {webEx.Data}");
                }
                
                _logger.LogError("HttpRequestException occurred checking NTLM accessibility for URL: {Url}. Exception: {Message}", url.AbsoluteUri, ex.Message);
                return APIResult<CAEnrollmentEndpoint>
                    .Failure(
                        $"HttpRequestException occurred checking NTLM accessibility for URL: {url}. Exception: {ex.Message}");
            } catch (HttpUnauthorizedException ex) {
                if (useBadChannelBinding == true) {
                    output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_NtlmChannelBindingRequired;
                    _logger.LogDebug("{Url} labeled as not vulnerable, NTLM channel binding is required", url.AbsoluteUri);
                    return APIResult<CAEnrollmentEndpoint>.Success(output);
                }

                _logger.LogError("Unauthorized exception checking NTLM accessibility for URL: {Url}. Exception: {Message}", url.AbsoluteUri, ex.Message);
                return APIResult<CAEnrollmentEndpoint>
                    .Failure(
                        $"401 Unauthorized exception checking NTLM accessibility for URL: {url}. Exception: {ex.Message}");
            } catch (HttpForbiddenException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathForbidden;
                _logger.LogDebug("{Url} labeled not vulnerable as the path was forbidden.", url.AbsoluteUri);
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (HttpServerErrorException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_PathNotFound;
                _logger.LogDebug("{Url} labeled not vulnerable as the path was not found.", url.AbsoluteUri);
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (MissingChallengeException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_NoNtlmChallenge;
                _logger.LogDebug("{Url} labeled not vulnerable as no NTLM challenge.", url.AbsoluteUri);
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (ExtendedProtectionMisconfiguredException) {
                output.Status = CAEnrollmentEndpointScanResult.NotVulnerable_EpaMisconfigured;
                _logger.LogDebug("{Url} labeled not vulnerable as EPA is misconfigured.", url.AbsoluteUri);
                return APIResult<CAEnrollmentEndpoint>
                    .Success(output);
            } catch (Exception ex) {
                _logger.LogError("An unhandled exception occurred checking NTLM accessibility for URL: {Url}. BadChannelBindings: {UseBadChannelBindings}. EndpointType: {EndpointType}. Exception: {Message}",
                    url.AbsoluteUri, useBadChannelBinding, type, ex.Message);
                return APIResult<CAEnrollmentEndpoint>
                    .Failure(
                        $"Unhandled exception checking NTLM accessibility for URL: {url}. BadChannelBindings: {useBadChannelBinding}.  Exception: {ex.Message}");
            }
        }
    }
}