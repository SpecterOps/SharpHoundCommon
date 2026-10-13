using SharpHoundCommonLib.Enums;
using SharpHoundCommonLib.OutputTypes;

namespace SharpHoundCommonLib
{
    public static class WellKnownPrincipal
    {
        public const string EveryoneSid = "S-1-1-0";

        /// <summary>
        ///     Gets the principal associated with a well known SID
        /// </summary>
        /// <param name="sid"></param>
        /// <param name="commonPrincipal"></param>
        /// <returns>True if SID matches a well known principal, false otherwise</returns>
        public static bool GetWellKnownPrincipal(string sid, out TypedPrincipal commonPrincipal)
        {
            commonPrincipal = sid switch
            {
                "S-1-0" => new TypedPrincipal("Null Authority", Label.User),
                "S-1-0-0" => new TypedPrincipal("Nobody", Label.User),
                "S-1-1" => new TypedPrincipal("World Authority", Label.User),
                EveryoneSid => new TypedPrincipal("Everyone", Label.Group),
                "S-1-2" => new TypedPrincipal("Local Authority", Label.User),
                "S-1-2-0" => new TypedPrincipal("Local", Label.Group),
                "S-1-2-1" => new TypedPrincipal("Console Logon", Label.Group),
                "S-1-3" => new TypedPrincipal("Creator Authority", Label.User),
                "S-1-3-0" => new TypedPrincipal("Creator Owner", Label.User),
                "S-1-3-1" => new TypedPrincipal("Creator Group", Label.Group),
                "S-1-3-2" => new TypedPrincipal("Creator Owner Server", Label.Computer),
                "S-1-3-3" => new TypedPrincipal("Creator Group Server", Label.Computer),
                "S-1-3-4" => new TypedPrincipal("Owner Rights", Label.Group),
                "S-1-4" => new TypedPrincipal("Non-unique Authority", Label.User),
                "S-1-5" => new TypedPrincipal("NT Authority", Label.User),
                "S-1-5-1" => new TypedPrincipal("Dialup", Label.Group),
                "S-1-5-2" => new TypedPrincipal("Network", Label.Group),
                "S-1-5-3" => new TypedPrincipal("Batch", Label.Group),
                "S-1-5-4" => new TypedPrincipal("Interactive", Label.Group),
                "S-1-5-6" => new TypedPrincipal("Service", Label.Group),
                "S-1-5-7" => new TypedPrincipal("Anonymous", Label.Group),
                "S-1-5-8" => new TypedPrincipal("Proxy", Label.Group),
                "S-1-5-9" => new TypedPrincipal("Enterprise Domain Controllers", Label.Group),
                "S-1-5-10" => new TypedPrincipal("Principal Self", Label.User),
                "S-1-5-11" => new TypedPrincipal("Authenticated Users", Label.Group),
                "S-1-5-12" => new TypedPrincipal("Restricted Code", Label.Group),
                "S-1-5-13" => new TypedPrincipal("Terminal Server Users", Label.Group),
                "S-1-5-14" => new TypedPrincipal("Remote Interactive Logon", Label.Group),
                "S-1-5-15" => new TypedPrincipal("This Organization", Label.Group),
                "S-1-5-17" => new TypedPrincipal("IUSR", Label.User),
                "S-1-5-18" => new TypedPrincipal("Local System", Label.User),
                "S-1-5-19" => new TypedPrincipal("Local Service", Label.User),
                "S-1-5-20" => new TypedPrincipal("Network Service", Label.User),
                "S-1-5-21-0-0-0-496" => new TypedPrincipal("Compounded Authentication", Label.Group),
                "S-1-5-21-0-0-0-497" => new TypedPrincipal("Claims Valid", Label.Group),
                "S-1-5-32-544" => new TypedPrincipal("Administrators", Label.Group),
                "S-1-5-32-545" => new TypedPrincipal("Users", Label.Group),
                "S-1-5-32-546" => new TypedPrincipal("Guests", Label.Group),
                "S-1-5-32-547" => new TypedPrincipal("Power Users", Label.Group),
                "S-1-5-32-548" => new TypedPrincipal("Account Operators", Label.Group),
                "S-1-5-32-549" => new TypedPrincipal("Server Operators", Label.Group),
                "S-1-5-32-550" => new TypedPrincipal("Print Operators", Label.Group),
                "S-1-5-32-551" => new TypedPrincipal("Backup Operators", Label.Group),
                "S-1-5-32-552" => new TypedPrincipal("Replicators", Label.Group),
                "S-1-5-32-554" => new TypedPrincipal("Pre-Windows 2000 Compatible Access", Label.Group),
                "S-1-5-32-555" => new TypedPrincipal("Remote Desktop Users", Label.Group),
                "S-1-5-32-556" => new TypedPrincipal("Network Configuration Operators", Label.Group),
                "S-1-5-32-557" => new TypedPrincipal("Incoming Forest Trust Builders", Label.Group),
                "S-1-5-32-558" => new TypedPrincipal("Performance Monitor Users", Label.Group),
                "S-1-5-32-559" => new TypedPrincipal("Performance Log Users", Label.Group),
                "S-1-5-32-560" => new TypedPrincipal("Windows Authorization Access Group", Label.Group),
                "S-1-5-32-561" => new TypedPrincipal("Terminal Server License Servers", Label.Group),
                "S-1-5-32-562" => new TypedPrincipal("Distributed COM Users", Label.Group),
                "S-1-5-32-568" => new TypedPrincipal("IIS_IUSRS", Label.Group),
                "S-1-5-32-569" => new TypedPrincipal("Cryptographic Operators", Label.Group),
                "S-1-5-32-573" => new TypedPrincipal("Event Log Readers", Label.Group),
                "S-1-5-32-574" => new TypedPrincipal("Certificate Service DCOM Access", Label.Group),
                "S-1-5-32-575" => new TypedPrincipal("RDS Remote Access Servers", Label.Group),
                "S-1-5-32-576" => new TypedPrincipal("RDS Endpoint Servers", Label.Group),
                "S-1-5-32-577" => new TypedPrincipal("RDS Management Servers", Label.Group),
                "S-1-5-32-578" => new TypedPrincipal("Hyper-V Administrators", Label.Group),
                "S-1-5-32-579" => new TypedPrincipal("Access Control Assistance Operators", Label.Group),
                "S-1-5-32-580" => new TypedPrincipal("Remote Management Users", Label.Group),
                "S-1-5-32-581" => new TypedPrincipal("System Managed Accounts Group", Label.Group),
                "S-1-5-32-582" => new TypedPrincipal("Storage Replica Administrators", Label.Group),
                "S-1-5-32-583" => new TypedPrincipal("Device Owners", Label.Group),
                "S-1-5-64-10" => new TypedPrincipal("NTLM Authentication", Label.Group),
                "S-1-5-64-14" => new TypedPrincipal("Schannel Authentication", Label.Group),
                "S-1-5-64-21" => new TypedPrincipal("Digest Authentication", Label.Group),
                "S-1-5-65-1" => new TypedPrincipal("This Organization Certificate", Label.Group),
                "S-1-5-80" => new TypedPrincipal("Service", Label.Group),
                "S-1-5-80-0" => new TypedPrincipal("All Services ", Label.Group),
                "S-1-5-82" => new TypedPrincipal("IIS AppPool", Label.Group),
                "S-1-5-90" => new TypedPrincipal("Window Manager\\Window Manager Group", Label.Group),
                "S-1-5-96" => new TypedPrincipal("Font Driver Host\\UMFD-0", Label.Computer),
                "S-1-5-113" => new TypedPrincipal("Local Account", Label.User),
                "S-1-5-114" => new TypedPrincipal("Local Account and Member of Administrators Group", Label.User),
                "S-1-5-1000" => new TypedPrincipal("Other Organization", Label.Group),
                "S-1-18-1" => new TypedPrincipal("Authentication Authority Asserted Identity", Label.Group),
                "S-1-18-2" => new TypedPrincipal("Service Asserted Identity", Label.Group),
                "S-1-18-3" => new TypedPrincipal("Fresh Public Key Identity", Label.Group),
                "S-1-18-4" => new TypedPrincipal("Key Trust", Label.Group),
                "S-1-18-5" => new TypedPrincipal("MFA Key Property", Label.Group),
                "S-1-18-6" => new TypedPrincipal("Attested Key Property", Label.Group),
                _ => null
            };

            return commonPrincipal != null;
        }
    }
}
