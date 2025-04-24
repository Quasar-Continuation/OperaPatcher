using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OperaPatcher
{
    internal class Program
    {
        #region Win32 API Imports

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out int lpNumberOfBytesRead);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModules(
            IntPtr hProcess,
            [Out] IntPtr[] lphModule,
            int cb,
            out int lpcbNeeded);

        [DllImport("psapi.dll")]
        private static extern uint GetModuleFileNameEx(
            IntPtr hProcess,
            IntPtr hModule,
            [Out] StringBuilder lpBaseName,
            int nSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetCursorInfo(ref CURSORINFO pci);

        #endregion Win32 API Imports

        #region Structs and Constants

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CURSORINFO
        {
            public int cbSize;
            public int flags;
            public IntPtr hCursor;
            public POINT ptScreenPos;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int x;
            public int y;
        }

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        #endregion Structs and Constants

        public static IntPtr RemoteGetProcAddress(int processId, string dllName, string functionName)
        {
            IntPtr processHandle = IntPtr.Zero;

            try
            {
                processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processId);
                if (processHandle == IntPtr.Zero)
                {
                    Console.WriteLine($"Failed to open process with ID {processId}. Error code: {GetLastError()}");
                    return IntPtr.Zero;
                }

                IntPtr localModuleHandle = LoadLibrary(dllName);
                if (localModuleHandle == IntPtr.Zero)
                {
                    Console.WriteLine($"Failed to load local module '{dllName}'. Error code: {GetLastError()}");
                    return IntPtr.Zero;
                }

                IntPtr localFunctionAddress = GetProcAddress(localModuleHandle, functionName);
                if (localFunctionAddress == IntPtr.Zero)
                {
                    Console.WriteLine($"Function '{functionName}' not found in '{dllName}'. Error code: {GetLastError()}");
                    return IntPtr.Zero;
                }

                long offset = localFunctionAddress.ToInt64() - localModuleHandle.ToInt64();
                Console.WriteLine($"Function offset: 0x{offset:X}");

                IntPtr remoteModuleBase = GetRemoteModuleHandle(processHandle, dllName);
                if (remoteModuleBase == IntPtr.Zero)
                {
                    Console.WriteLine($"Module '{dllName}' not found in process {processId}");
                    return IntPtr.Zero;
                }

                IntPtr remoteFunctionAddress = new IntPtr(remoteModuleBase.ToInt64() + offset);
                Console.WriteLine($"Remote function address: 0x{remoteFunctionAddress.ToInt64():X}");

                return remoteFunctionAddress;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in RemoteGetProcAddress: {ex.Message}");
                return IntPtr.Zero;
            }
            finally
            {
                // Clean
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }
        }

        private static IntPtr GetRemoteModuleHandle(IntPtr processHandle, string moduleName)
        {
            IntPtr[] moduleHandles = new IntPtr[1024];
            int bytesNeeded;

            if (!EnumProcessModules(processHandle, moduleHandles, Marshal.SizeOf(typeof(IntPtr)) * moduleHandles.Length, out bytesNeeded))
            {
                Console.WriteLine($"Failed to enumerate modules. Error code: {GetLastError()}");
                return IntPtr.Zero;
            }

            int moduleCount = bytesNeeded / Marshal.SizeOf(typeof(IntPtr));
            StringBuilder moduleNameBuffer = new StringBuilder(256);

            string targetName = moduleName.ToLower();

            for (int i = 0; i < moduleCount; i++)
            {
                GetModuleFileNameEx(processHandle, moduleHandles[i], moduleNameBuffer, moduleNameBuffer.Capacity);
                string currentModuleName = moduleNameBuffer.ToString();

                string fileName = System.IO.Path.GetFileName(currentModuleName).ToLower();

                if (fileName == targetName || fileName == targetName + ".dll")
                {
                    return moduleHandles[i];
                }
            }

            return IntPtr.Zero;
        }

        public static bool EnableDebugPrivilege(int processId)
        {
            IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)processId);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open process.");
                return false;
            }

            if (!OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr tokenHandle))
            {
                Console.WriteLine("Failed to open process token.");
                CloseHandle(processHandle);
                return false;
            }

            LUID luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
            {
                Console.WriteLine("Failed to lookup privilege value.");
                CloseHandle(tokenHandle);
                CloseHandle(processHandle);
                return false;
            }

            TOKEN_PRIVILEGES tokenPrivileges = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SE_PRIVILEGE_ENABLED
            };

            if (!AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("Failed to adjust token privileges.");
                CloseHandle(tokenHandle);
                CloseHandle(processHandle);
                return false;
            }

            CloseHandle(tokenHandle);
            CloseHandle(processHandle);
            return true;
        }

        public static bool FixOpera(int pid)
        {
            IntPtr addr = RemoteGetProcAddress(pid, "user32.dll", "GetCursorInfo");
            if (addr == IntPtr.Zero)
            {
                Console.WriteLine("Failed to find GetCursorInfo function address");
                return false;
            }

            Console.WriteLine($"GetCursorInfo address: 0x{addr.ToInt64():X}");

            // mov eax, 1; ret
            byte[] patchBytes = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

            IntPtr handle = OpenProcess(PROCESS_ALL_ACCESS, false, (uint)pid);
            if (handle == IntPtr.Zero)
            {
                Console.WriteLine($"Failed to open process. Error: {GetLastError()}");
                return false;
            }

            try
            {
                uint oldProtect = 0;
                if (!VirtualProtectEx(handle, addr, (uint)patchBytes.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
                {
                    Console.WriteLine($"Failed to change memory protection. Error: {GetLastError()}");
                    return false;
                }

                int bytesWritten = 0;
                if (!WriteProcessMemory(handle, addr, patchBytes, patchBytes.Length, ref bytesWritten))
                {
                    Console.WriteLine($"Failed to write to process memory. Error: {GetLastError()}");
                    return false;
                }

                Console.WriteLine($"Successfully wrote {bytesWritten} bytes");

                byte[] verifyBuffer = new byte[patchBytes.Length];
                int bytesRead = 0;
                if (ReadProcessMemory(handle, addr, verifyBuffer, (uint)verifyBuffer.Length, out bytesRead))
                {
                    bool patchVerified = bytesRead == patchBytes.Length;
                    for (int i = 0; i < bytesRead && patchVerified; i++)
                    {
                        if (verifyBuffer[i] != patchBytes[i])
                        {
                            patchVerified = false;
                        }
                    }

                    if (patchVerified)
                    {
                        Console.WriteLine("Patch verified successfully");
                    }
                    else
                    {
                        Console.WriteLine("Patch verification failed");
                    }
                }

                uint dummy;
                VirtualProtectEx(handle, addr, (uint)patchBytes.Length, oldProtect, out dummy);

                return bytesWritten == patchBytes.Length;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        private static void Main(string[] args)
        {
            CURSORINFO cursorInfo = new CURSORINFO();
            cursorInfo.cbSize = Marshal.SizeOf(typeof(CURSORINFO));
            if (GetCursorInfo(ref cursorInfo))
            {
                Console.WriteLine($"Cursor Position: {cursorInfo.ptScreenPos.x}, {cursorInfo.ptScreenPos.y}");
                Console.WriteLine($"Cursor Handle: {cursorInfo.hCursor}");
            }
            else
            {
                Console.WriteLine("Failed to get cursor info");
            }

            int pid;
            Process[] operaProcesses = Process.GetProcessesByName("opera").Where(p => p.MainWindowHandle != IntPtr.Zero).ToArray();

            if (operaProcesses.Length > 0)
            {
                pid = operaProcesses[0].Id;
                Console.WriteLine($"Found Opera process with PID: {pid}");
            }
            else
            {
                Console.Write("Enter Opera process ID: ");
                if (!int.TryParse(Console.ReadLine(), out pid))
                {
                    Console.WriteLine("Invalid process ID");
                    return;
                }
            }

            if (EnableDebugPrivilege(pid))
            {
                Console.WriteLine("Debug privilege enabled successfully.");
            }
            else
            {
                Console.WriteLine("Failed to enable debug privilege.");
                Console.WriteLine("This tool might not work without administrator privileges.");
                Console.WriteLine("Press any key to continue anyway...");
                Console.ReadKey();
            }

            Console.WriteLine($"Fixing Opera PID: {pid}");
            if (FixOpera(pid))
            {
                Console.WriteLine($"===========Fixed Opera PID: {pid}===============");
            }
            else
            {
                Console.WriteLine($"Failed to fix Opera PID: {pid}");
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}