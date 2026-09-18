using System;
using System.Runtime.InteropServices;
using System.Security;
using SharpHoundRPC.Handles;
using SharpHoundRPC.Shared;

namespace SharpHoundRPC.SAMRPCNative
{
    [SuppressUnmanagedCodeSecurity]
    public static class SAMMethods
    {
        internal static (NtStatus status, SAMHandle handle) SamConnect(string serverName,
            SAMEnums.SamAccessMasks requestedConnectAccess)
        {
            var us = new SharedStructs.UnicodeString(serverName);
            var objectAttributes = default(SAMStructs.ObjectAttributes);

            var status = SamConnect(ref us, out var handle, requestedConnectAccess, ref objectAttributes);
            objectAttributes.Dispose();

            return (status, handle);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamConnect(
            ref SharedStructs.UnicodeString serverName,
            out SAMHandle serverHandle,
            SAMEnums.SamAccessMasks desiredAccess,
            ref SAMStructs.ObjectAttributes objectAttributes
        );

        internal static (NtStatus status, SAMPointer domainRids, int count)
            SamEnumerateDomainsInSamServer(SAMHandle serverHandle)
        {
            var enumerationContext = 0;
            var status =
                SamEnumerateDomainsInSamServer(serverHandle, ref enumerationContext, out var domains, -1,
                    out var count);
            
            return (status, domains, count);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamEnumerateDomainsInSamServer(
            SAMHandle serverHandle,
            ref int enumerationContext,
            out SAMPointer buffer,
            int prefMaxLen,
            out int count
        );

        internal static (NtStatus status, SAMPointer securityIdentifier) SamLookupDomainInSamServer(
            SAMHandle serverHandle, string name)
        {
            var us = new SharedStructs.UnicodeString(name);
            var status = SamLookupDomainInSamServer(serverHandle, ref us, out var sid);
            
            return (status, sid);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamLookupDomainInSamServer(
            SAMHandle serverHandle,
            ref SharedStructs.UnicodeString name,
            out SAMPointer sid);

        internal static (NtStatus status, SAMHandle domainHandle) SamOpenDomain(SAMHandle serverHandle,
            SAMEnums.DomainAccessMask desiredAccess, byte[] domainSid)
        {
            var status = SamOpenDomain(serverHandle, desiredAccess, domainSid, out var domainHandle);
            return (status, domainHandle);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenDomain(
            SAMHandle serverHandle,
            SAMEnums.DomainAccessMask desiredAccess,
            [MarshalAs(UnmanagedType.LPArray)] byte[] domainSid,
            out SAMHandle domainHandle
        );

        internal static (NtStatus status, SAMSidArray members, int count) SamGetMembersInAlias(SAMHandle aliasHandle)
        {
            var status = SamGetMembersInAlias(aliasHandle, out var members, out var count);
            return (status, members, count);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamGetMembersInAlias(
            SAMHandle aliasHandle,
            out SAMSidArray members,
            out int count
        );

        internal static (NtStatus status, SAMHandle aliasHandle) SamOpenAlias(SAMHandle domainHandle,
            SAMEnums.AliasOpenFlags desiredAccess, int aliasId)
        {
            var status = SamOpenAlias(domainHandle, desiredAccess, aliasId, out var aliasHandle);
            return (status, aliasHandle);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamOpenAlias(
            SAMHandle domainHandle,
            SAMEnums.AliasOpenFlags desiredAccess,
            int aliasId,
            out SAMHandle aliasHandle
        );

        internal static (NtStatus status, SAMPointer pointer, int count) SamEnumerateAliasesInDomain(
            SAMHandle domainHandle)
        {
            var enumerationContext = 0;
            var status = SamEnumerateAliasesInDomain(domainHandle, ref enumerationContext, out var buffer, -1,
                out var count);
            return (status, buffer, count);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamEnumerateAliasesInDomain(
            SAMHandle domainHandle,
            ref int enumerationContext,
            out SAMPointer buffer,
            int prefMaxLen,
            out int count
        );

        internal static (NtStatus status, SAMPointer names, SAMPointer use) SamLookupIdsInDomain(SAMHandle domainHandle,
            int rid)
        {
            var rids = new[] {rid};
            var status = SamLookupIdsInDomain(domainHandle, 1, rids, out var names, out var use);
            return (status, names, use);
        }

        [DllImport("samlib.dll", CharSet = CharSet.Unicode)]
        private static extern NtStatus SamLookupIdsInDomain(SAMHandle domainHandle,
            int count,
            int[] rids,
            out SAMPointer names,
            out SAMPointer use);

        #region Cleanup

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamFreeMemory(
            IntPtr handle
        );

        [DllImport("samlib.dll")]
        internal static extern NtStatus SamCloseHandle(
            IntPtr handle
        );

        #endregion
    }
}