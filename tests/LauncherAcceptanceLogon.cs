// SPDX-FileCopyrightText: 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-only
// Project: https://github.com/fmuecke/launch-as

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace LaunchAs
{
    public sealed class AcceptanceLogonV2 : IDisposable
    {
        private const int Logon32LogonInteractive = 2;
        private const int Logon32ProviderDefault = 0;
        private const int LogonWithProfile = 1;
        private const int CreateNewConsole = 0x00000010;
        private const int TokenGroups = 2;
        private const int ErrorInsufficientBuffer = 122;
        private const uint SeGroupLogonId = 0xC0000000;

        private InteractiveObjectAclV1 interactiveAcl;
        public int ProcessId { get; private set; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int Size;
            public string Reserved;
            public string Desktop;
            public string Title;
            public int X;
            public int Y;
            public int XSize;
            public int YSize;
            public int XCountChars;
            public int YCountChars;
            public int FillAttribute;
            public int Flags;
            public short ShowWindow;
            public short Reserved2Size;
            public IntPtr Reserved2;
            public IntPtr StandardInput;
            public IntPtr StandardOutput;
            public IntPtr StandardError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr Process;
            public IntPtr Thread;
            public int ProcessId;
            public int ThreadId;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LogonUser(
            string userName, string domain, string password, int logonType,
            int logonProvider, out IntPtr token);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessWithTokenW(
            IntPtr token, int logonFlags,
            string applicationName, StringBuilder commandLine, int creationFlags,
            IntPtr environment, string currentDirectory, ref StartupInfo startupInfo,
            out ProcessInformation processInformation);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr token, int informationClass, IntPtr information,
            int informationLength, out int returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private static SecurityIdentifier GetLogonSid(IntPtr token)
        {
            int returnLength;
            if (!GetTokenInformation(token, TokenGroups, IntPtr.Zero, 0, out returnLength))
            {
                int error = Marshal.GetLastWin32Error();
                if (error != ErrorInsufficientBuffer)
                {
                    throw new Win32Exception(error);
                }
            }
            IntPtr buffer = Marshal.AllocHGlobal(returnLength);
            try
            {
                if (!GetTokenInformation(
                        token, TokenGroups, buffer, returnLength, out returnLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                int groupCount = Marshal.ReadInt32(buffer);
                int firstGroupOffset = IntPtr.Size == 8 ? 8 : 4;
                int groupSize = IntPtr.Size == 8 ? 16 : 8;
                for (int index = 0; index < groupCount; ++index)
                {
                    IntPtr group = IntPtr.Add(buffer, firstGroupOffset + index * groupSize);
                    IntPtr sidPointer = Marshal.ReadIntPtr(group);
                    uint attributes = unchecked((uint)Marshal.ReadInt32(group, IntPtr.Size));
                    if ((attributes & SeGroupLogonId) == SeGroupLogonId)
                    {
                        return new SecurityIdentifier(sidPointer);
                    }
                }
                throw new InvalidOperationException(
                    "The standard caller token does not contain a logon SID (S-1-5-5-*)."
                );
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static AcceptanceLogonV2 Start(
            string userName, string domain, string password,
            string applicationName, string commandLine, string currentDirectory)
        {
            IntPtr token;
            if (!LogonUser(userName, domain, password, Logon32LogonInteractive,
                    Logon32ProviderDefault, out token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            InteractiveObjectAclV1 interactiveAcl = null;
            try
            {
                SecurityIdentifier logonSid = GetLogonSid(token);
                interactiveAcl = InteractiveObjectAclV1.Grant(logonSid.Value);

                var startupInfo = new StartupInfo
                {
                    Size = Marshal.SizeOf<StartupInfo>(),
                    Desktop = @"winsta0\default"
                };
                ProcessInformation processInformation;
                if (!CreateProcessWithTokenW(token, LogonWithProfile, applicationName,
                        new StringBuilder(commandLine), CreateNewConsole,
                        IntPtr.Zero, currentDirectory, ref startupInfo, out processInformation))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                try
                {
                    var result = new AcceptanceLogonV2
                    {
                        ProcessId = processInformation.ProcessId,
                        interactiveAcl = interactiveAcl
                    };
                    interactiveAcl = null;
                    return result;
                }
                finally
                {
                    CloseHandle(processInformation.Thread);
                    CloseHandle(processInformation.Process);
                }
            }
            finally
            {
                if (interactiveAcl != null)
                {
                    interactiveAcl.Dispose();
                }
                CloseHandle(token);
            }
        }

        public void Dispose()
        {
            if (interactiveAcl != null)
            {
                interactiveAcl.Dispose();
                interactiveAcl = null;
            }
        }
    }

    public sealed class InteractiveObjectAclV1 : IDisposable
    {
        private const int DaclSecurityInformation = 0x00000004;
        private const int ErrorInsufficientBuffer = 122;
        private const int ReadControl = 0x00020000;
        private const int WriteDac = 0x00040000;
        private const int WindowStationAllAccess = 0x000F037F;
        private const int DesktopAllAccess = 0x000F01FF;

        private IntPtr windowStation;
        private IntPtr desktop;
        private IntPtr namedObjectDirectory;
        private byte[] originalWindowStation;
        private byte[] originalDesktop;
        private byte[] originalNamedObjectDirectory;

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtOpenDirectoryObject(
            out IntPtr handle, int desiredAccess, ref ObjectAttributes attributes);

        [DllImport("ntdll.dll")]
        private static extern int RtlNtStatusToDosError(int status);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetKernelObjectSecurity(
            IntPtr handle, int requestedInformation, byte[] securityDescriptor,
            int length, out int lengthNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetKernelObjectSecurity(
            IntPtr handle, int requestedInformation, byte[] securityDescriptor);

        private static IntPtr OpenNamedObjectDirectory()
        {
            string path = @"\Sessions\" +
                System.Diagnostics.Process.GetCurrentProcess().SessionId + @"\BaseNamedObjects";
            var name = new UnicodeString
            {
                Length = checked((ushort)(path.Length * 2)),
                MaximumLength = checked((ushort)(path.Length * 2)),
                Buffer = Marshal.StringToHGlobalUni(path)
            };
            IntPtr namePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            try
            {
                Marshal.StructureToPtr(name, namePointer, false);
                var attributes = new ObjectAttributes
                {
                    Length = Marshal.SizeOf<ObjectAttributes>(),
                    ObjectName = namePointer
                };
                IntPtr handle;
                int status = NtOpenDirectoryObject(out handle, ReadControl | WriteDac, ref attributes);
                if (status < 0)
                {
                    throw new Win32Exception(RtlNtStatusToDosError(status));
                }
                return handle;
            }
            finally
            {
                Marshal.FreeHGlobal(namePointer);
                Marshal.FreeHGlobal(name.Buffer);
            }
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenWindowStation(
            string name, bool inherit, int desiredAccess);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenDesktop(
            string name, int flags, bool inherit, int desiredAccess);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseWindowStation(IntPtr windowStation);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool CloseDesktop(IntPtr desktop);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetUserObjectSecurity(
            IntPtr handle, ref int requestedInformation, byte[] securityDescriptor,
            int length, out int lengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetUserObjectSecurity(
            IntPtr handle, ref int requestedInformation, byte[] securityDescriptor);

        private InteractiveObjectAclV1(string accountSid, bool namedObjectsOnly)
        {
            int desiredAccess = ReadControl | WriteDac;
            if (!namedObjectsOnly)
            {
                windowStation = OpenWindowStation("WinSta0", false, desiredAccess);
                if (windowStation == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                desktop = OpenDesktop("Default", 0, false, desiredAccess);
                if (desktop == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    CloseWindowStation(windowStation);
                    windowStation = IntPtr.Zero;
                    throw new Win32Exception(error);
                }
            }

            try
            {
                namedObjectDirectory = OpenNamedObjectDirectory();
                var sid = new SecurityIdentifier(accountSid);
                if (!namedObjectsOnly)
                {
                    originalWindowStation = ReadSecurityDescriptor(windowStation);
                    originalDesktop = ReadSecurityDescriptor(desktop);
                    Grant(windowStation, originalWindowStation, sid, WindowStationAllAccess);
                    Grant(desktop, originalDesktop, sid, DesktopAllAccess);
                }
                originalNamedObjectDirectory = ReadSecurityDescriptor(namedObjectDirectory, true);
                // The synthetic caller acts as the guest's session owner, including the
                // directory rights needed to create objects and coordinate target leases.
                Grant(namedObjectDirectory, originalNamedObjectDirectory, sid,
                    ReadControl | WriteDac | 0x000F, true);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public static InteractiveObjectAclV1 Grant(string accountSid)
        {
            return new InteractiveObjectAclV1(accountSid, false);
        }

        public static InteractiveObjectAclV1 GrantNamedObjectDirectory(string accountSid)
        {
            return new InteractiveObjectAclV1(accountSid, true);
        }

        private static byte[] ReadSecurityDescriptor(IntPtr handle, bool kernelObject = false)
        {
            int requestedInformation = DaclSecurityInformation;
            int lengthNeeded;
            bool queried = kernelObject
                ? GetKernelObjectSecurity(handle, requestedInformation, null, 0, out lengthNeeded)
                : GetUserObjectSecurity(handle, ref requestedInformation, null, 0, out lengthNeeded);
            if (!queried)
            {
                int error = Marshal.GetLastWin32Error();
                if (error != ErrorInsufficientBuffer)
                {
                    throw new Win32Exception(error);
                }
            }
            var descriptor = new byte[lengthNeeded];
            queried = kernelObject
                ? GetKernelObjectSecurity(handle, requestedInformation, descriptor,
                    descriptor.Length, out lengthNeeded)
                : GetUserObjectSecurity(handle, ref requestedInformation, descriptor,
                    descriptor.Length, out lengthNeeded);
            if (!queried)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return descriptor;
        }

        private static void Grant(IntPtr handle, byte[] original,
            SecurityIdentifier sid, int accessMask, bool kernelObject = false)
        {
            var descriptor = new RawSecurityDescriptor(original, 0);
            RawAcl dacl = descriptor.DiscretionaryAcl ?? new RawAcl(2, 1);
            dacl.InsertAce(dacl.Count, new CommonAce(
                AceFlags.None, AceQualifier.AccessAllowed, accessMask, sid, false, null));
            descriptor.DiscretionaryAcl = dacl;
            var updated = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(updated, 0);
            WriteSecurityDescriptor(handle, updated, kernelObject);
        }

        private static void WriteSecurityDescriptor(
            IntPtr handle, byte[] descriptor, bool kernelObject = false)
        {
            int requestedInformation = DaclSecurityInformation;
            bool written = kernelObject
                ? SetKernelObjectSecurity(handle, requestedInformation, descriptor)
                : SetUserObjectSecurity(handle, ref requestedInformation, descriptor);
            if (!written)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        public void Dispose()
        {
            try
            {
                if (namedObjectDirectory != IntPtr.Zero && originalNamedObjectDirectory != null)
                {
                    WriteSecurityDescriptor(namedObjectDirectory, originalNamedObjectDirectory, true);
                }
                if (desktop != IntPtr.Zero && originalDesktop != null)
                {
                    WriteSecurityDescriptor(desktop, originalDesktop);
                }
                if (windowStation != IntPtr.Zero && originalWindowStation != null)
                {
                    WriteSecurityDescriptor(windowStation, originalWindowStation);
                }
            }
            finally
            {
                if (namedObjectDirectory != IntPtr.Zero)
                {
                    CloseHandle(namedObjectDirectory);
                    namedObjectDirectory = IntPtr.Zero;
                }
                if (desktop != IntPtr.Zero)
                {
                    CloseDesktop(desktop);
                    desktop = IntPtr.Zero;
                }
                if (windowStation != IntPtr.Zero)
                {
                    CloseWindowStation(windowStation);
                    windowStation = IntPtr.Zero;
                }
            }
        }
    }
}
