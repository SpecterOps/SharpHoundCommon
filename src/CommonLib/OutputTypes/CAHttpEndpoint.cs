using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpHoundCommonLib.OutputTypes {
    public enum CAEnrollmentEndpointType {
        // The Certificate Authority Web Enrollment server role, an ASP web application
        WebEnrollmentApplication,

        // The Certificate Enrollment Web Service (CES) server role, a SOAP-based web service
        EnrollmentWebService,

        // The Network Device Enrollment Service (NDES), which uses the SCEP protocol to obtain certificates.
        NDES, // NDES

        // ICertPassage Remote Protocol (MS-ICPR), an RPC protcol
        RPC, // 

        // The Windows Client Certificate Enrollment Protocol (MS-WCCE), a set of DCOM interfaces for certificate enrollment
        DCOM,
    }

    public enum CAEnrollmentEndpointScanResult {
        // Endpoint is vulnerable due to using HTTP (not HTTPS) with NTLM auth (ESC8)
        Vulnerable_NtlmHttpEndpoint,

        // Endpoint is vulnerable due to using HTTP (not HTTPS) with Kerberos auth
        Vulnerable_KerberosHttpEndpoint,

        // Endpoint is vulnerable due to not requiring channel binding for the HTTPS endpoint (ESC8)
        Vulnerable_NtlmHttpsNoChannelBinding,


        // Offset the not vulnerable conditions in case we want to add additional

        // Endpoint is not vulnerable due to not existing
        NotVulnerable_PortInaccessible = 0x100,

        // The server did not return an NTLM challenge (e.g., when Negotiate:Kerberos is enabled)
        NotVulnerable_NoNtlmChallenge,

        // 404 NotFound when accessing the endpoint
        NotVulnerable_PathNotFound,

        // Returned if the IIS is configured to require SSL (so no HTTP possible)
        NotVulnerable_PathForbidden,

        // 500 Server Error when visiting a Url
        NotVulnerable_ServerError,

        // Endpoint is not vulnerable due requiring ChannelBinding or only supporting Kerberos authentication (or both)
        NotVulnerable_NtlmChannelBindingRequired,

        Error = 0xFFFF
    }

    public class CAEnrollmentEndpoint(Uri url, CAEnrollmentEndpointType type, CAEnrollmentEndpointScanResult status) {
        public Uri Url { get; set; } = url;
        public CAEnrollmentEndpointType Type { get; set; } = type;
        public CAEnrollmentEndpointScanResult Status { get; set; } = status;
    }
}