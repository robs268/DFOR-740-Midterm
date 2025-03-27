/***********************************************************
 * Robert Schwartz
 * DFOR 740
 * Spring 2025
 * RobsTaskList Program
 ***********************************************************/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.IO;

namespace TasklistApp
{
    class Program
    {
        #region Win32 API Imports and Structures

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll")]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule,
            [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] int nSize);

        [DllImport("kernel32.dll")]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags,
            [Out] StringBuilder lpExeName, ref uint lpdwSize);

        [Flags]
        enum ProcessAccessFlags : uint
        {
            QueryLimitedInformation = 0x00001000,
            QueryInformation = 0x00000400,
            VirtualMemoryRead = 0x00000010,
            VMRead = 0x00000010
        }

        // For WTS functions to get session information
        [DllImport("wtsapi32.dll")]
        private static extern bool WTSEnumerateProcesses(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppProcessInfo,
            ref int pCount);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr memory);

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_PROCESS_INFO
        {
            public int SessionId;
            public int ProcessId;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string pProcessName;
            public IntPtr pUserSid;
        }

        // For NtQuerySystemInformation to get process information including parent process IDs
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            ref int ReturnLength);

        private const int SystemProcessInformation = 5;

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_PROCESS_INFORMATION
        {
            public int NextEntryOffset;
            public int NumberOfThreads;
            public long SpareLi1;
            public long SpareLi2;
            public long SpareLi3;
            public long CreateTime;
            public long UserTime;
            public long KernelTime;
            public UNICODE_STRING ImageName;
            public int BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;  // Parent process ID
            public int HandleCount;
            public int SessionId;
            public IntPtr PageDirectoryBase;
            public IntPtr PeakVirtualSize;
            public IntPtr VirtualSize;
            public uint PageFaultCount;
            public IntPtr PeakWorkingSetSize;
            public IntPtr WorkingSetSize;
            public IntPtr QuotaPeakPagedPoolUsage;
            public IntPtr QuotaPagedPoolUsage;
            public IntPtr QuotaPeakNonPagedPoolUsage;
            public IntPtr QuotaNonPagedPoolUsage;
            public IntPtr PagefileUsage;
            public IntPtr PeakPagefileUsage;
            public IntPtr PrivatePageCount;
            public long ReadOperationCount;
            public long WriteOperationCount;
            public long OtherOperationCount;
            public long ReadTransferCount;
            public long WriteTransferCount;
            public long OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // For SC_ENUM_TYPE to enumerate services
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", EntryPoint = "EnumServicesStatusExW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool EnumServicesStatusEx(
            IntPtr hSCManager,
            int infoLevel,
            uint serviceType,
            uint serviceState,
            IntPtr lpServices,
            uint cbBufSize,
            out uint pcbBytesNeeded,
            out uint lpServicesReturned,
            ref uint lpResumeHandle,
            string pszGroupName);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle", ExactSpelling = true, SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SERVICE_STATUS_PROCESS
        {
            public uint dwServiceType;
            public uint dwCurrentState;
            public uint dwControlsAccepted;
            public uint dwWin32ExitCode;
            public uint dwServiceSpecificExitCode;
            public uint dwCheckPoint;
            public uint dwWaitHint;
            public uint dwProcessId;
            public uint dwServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct ENUM_SERVICE_STATUS_PROCESS
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpServiceName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpDisplayName;
            public SERVICE_STATUS_PROCESS ServiceStatus;
        }

        private const int SC_MANAGER_CONNECT = 0x0001;
        private const int SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        private const int SC_ENUM_PROCESS_INFO = 0;
        private const uint SERVICE_WIN32 = 0x00000030;
        private const uint SERVICE_ACTIVE = 0x00000001;
        #endregion

        // Process information structure to hold all the data we need
        class ProcessInfo
        {
            public string ImageName { get; set; }
            public int PID { get; set; }
            public string SessionName { get; set; }
            public int SessionId { get; set; }
            public string MemUsage { get; set; }
            public int PPID { get; set; } // Parent Process ID
            public string Status { get; set; }
            public string Username { get; set; }
            public int ThreadCount { get; set; }
            public string WindowTitle { get; set; }
            public List<string> Services { get; set; } = new List<string>();
            public string Modules { get; set; }
        }

        static void Main(string[] args)
        {
            // Check if help is requested
            if (args.Length > 0 && ( args.Contains("/?") || args.Contains("--help", StringComparer.OrdinalIgnoreCase) || args.Contains("/h", StringComparer.OrdinalIgnoreCase) || args.Contains("/help", StringComparer.OrdinalIgnoreCase)))
            {
                DisplayHelp();
                return;
            }

            // Parse command line arguments to determine which parameters were specified
            var parameters = ParseCommandLine(args);

            // Get the list of all processes with basic information
            List<ProcessInfo> processes = GetAllProcessInfo();

            // Apply filters based on command-line parameters
            if (parameters.ContainsKey("/FI") && parameters["/FI"] != null)
            {
                foreach (var filter in parameters["/FI"])
                {
                    processes = ApplyFilter(processes, filter);
                }
            }

            // Show output based on format parameters
            if (parameters.ContainsKey("/SVC"))
            {
                // Check if we should only show processes with services
                bool onlyWithServices = parameters.ContainsKey("/SVCO");

                // Display processes with services
                DisplayProcessesWithServices(processes, onlyWithServices);
            }
            else if (parameters.ContainsKey("/M"))
            {
                // Display processes with modules
                DisplayProcessesWithModules(processes, parameters["/M"]?.FirstOrDefault());
            }
            else if (parameters.ContainsKey("/V"))
            {
                // Display verbose information
                DisplayVerboseProcesses(processes);
            }
            else
            {
                // Display standard process listing
                DisplayStandardProcesses(processes);
            }
        }

        #region Command line parsing

        private static Dictionary<string, List<string>> ParseCommandLine(string[] args)
        {
            var parameters = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            // Add parameters that don't need values
            string[] simpleParams = { "/SVC", "/SVCO", "/V", "/NH" };
            foreach (var param in simpleParams)
            {
                if (args.Contains(param, StringComparer.OrdinalIgnoreCase))
                {
                    parameters[param] = new List<string>();
                }
            }

            // Parse parameters that take values
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToUpper();

                if (arg == "/FI" && i + 1 < args.Length)
                {
                    if (!parameters.ContainsKey("/FI"))
                        parameters["/FI"] = new List<string>();

                    parameters["/FI"].Add(args[i + 1]);
                    i++; // Skip the next argument since we've processed it
                }
                else if (arg == "/M" && i + 1 < args.Length)
                {
                    parameters["/M"] = new List<string> { args[i + 1] };
                    i++;
                }
                else if (arg == "/S" && i + 1 < args.Length)
                {
                    parameters["/S"] = new List<string> { args[i + 1] };
                    i++;
                }
                else if (arg == "/U" && i + 1 < args.Length)
                {
                    parameters["/U"] = new List<string> { args[i + 1] };
                    i++;
                }
                else if (arg == "/P" && i + 1 < args.Length)
                {
                    parameters["/P"] = new List<string> { args[i + 1] };
                    i++;
                }
                else if (arg == "/FO" && i + 1 < args.Length)
                {
                    parameters["/FO"] = new List<string> { args[i + 1] };
                    i++;
                }
            }

            return parameters;
        }

        #endregion

        #region Process Information Gathering

        private static List<ProcessInfo> GetAllProcessInfo()
        {
            var processes = new List<ProcessInfo>();

            try
            {
                // Get all processes
                Process[] processArray = Process.GetProcesses();

                // Get service information using Windows API instead of WMI
                Dictionary<int, List<string>> serviceMap = GetServiceProcessMapNative();

                // Get parent process IDs using Native API instead of WMI
                var parentProcessMap = GetParentProcessMapNative();

                foreach (Process proc in processArray)
                {
                    try
                    {
                        var processInfo = new ProcessInfo
                        {
                            ImageName = proc.ProcessName + ".exe",
                            PID = proc.Id,
                            SessionId = proc.SessionId,
                            MemUsage = FormatBytes(proc.WorkingSet64),
                            PPID = parentProcessMap.ContainsKey(proc.Id) ? parentProcessMap[proc.Id] : 0
                        };

                        // Get associated services
                        if (serviceMap.ContainsKey(proc.Id))
                        {
                            processInfo.Services = serviceMap[proc.Id];
                        }

                        // Add to our list
                        processes.Add(processInfo);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error processing PID {proc.Id}: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error gathering process information: {ex.Message}");
            }

            return processes;
        }

        private static Dictionary<int, int> GetParentProcessMapNative()
        {
            var parentProcessMap = new Dictionary<int, int>();

            try
            {
                // First call to get the required buffer size
                int bufferSize = 0;
                NtQuerySystemInformation(SystemProcessInformation, IntPtr.Zero, 0, ref bufferSize);

                // Allocate memory for the buffer
                IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

                try
                {
                    // Get the actual process information
                    int returnLength = 0;
                    int status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, ref returnLength);

                    if (status == 0) // STATUS_SUCCESS
                    {
                        // Process the returned information
                        IntPtr current = buffer;

                        while (true)
                        {
                            SYSTEM_PROCESS_INFORMATION process = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(current, typeof(SYSTEM_PROCESS_INFORMATION));

                            // Convert process ID and parent process ID to integers
                            int processId = process.UniqueProcessId.ToInt32();
                            int parentProcessId = process.InheritedFromUniqueProcessId.ToInt32();

                            // Add to our map
                            if (processId > 0)
                            {
                                parentProcessMap[processId] = parentProcessId;
                            }

                            // Move to the next process entry
                            if (process.NextEntryOffset == 0)
                                break;

                            current = IntPtr.Add(current, process.NextEntryOffset);
                        }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error retrieving parent process information: {ex.Message}");
            }

            return parentProcessMap;
        }

        private static Dictionary<int, List<string>> GetServiceProcessMapNative()
        {
            Dictionary<int, List<string>> serviceMap = new Dictionary<int, List<string>>();

            try
            {
                // Open the service control manager
                IntPtr scmHandle = OpenSCManager(null, null, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

                if (scmHandle == IntPtr.Zero)
                {
                    throw new Exception($"OpenSCManager failed: {Marshal.GetLastWin32Error()}");
                }

                try
                {
                    // First call to get the required buffer size
                    uint bytesNeeded = 0;
                    uint servicesReturned = 0;
                    uint resumeHandle = 0;

                    EnumServicesStatusEx(
                        scmHandle,
                        SC_ENUM_PROCESS_INFO,
                        SERVICE_WIN32,
                        SERVICE_ACTIVE,
                        IntPtr.Zero,
                        0,
                        out bytesNeeded,
                        out servicesReturned,
                        ref resumeHandle,
                        null);

                    // Allocate memory for the buffer
                    IntPtr buffer = Marshal.AllocHGlobal((int)bytesNeeded);

                    try
                    {
                        // Get the actual service information
                        resumeHandle = 0;

                        if (EnumServicesStatusEx(
                            scmHandle,
                            SC_ENUM_PROCESS_INFO,
                            SERVICE_WIN32,
                            SERVICE_ACTIVE,
                            buffer,
                            bytesNeeded,
                            out bytesNeeded,
                            out servicesReturned,
                            ref resumeHandle,
                            null))
                        {
                            // Process each service
                            int structSize = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));

                            for (int i = 0; i < servicesReturned; i++)
                            {
                                IntPtr structPtr = new IntPtr(buffer.ToInt64() + i * structSize);
                                ENUM_SERVICE_STATUS_PROCESS serviceStatus = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(
                                    structPtr, typeof(ENUM_SERVICE_STATUS_PROCESS));

                                // Get the process ID and service name
                                int processId = (int)serviceStatus.ServiceStatus.dwProcessId;
                                string serviceName = serviceStatus.lpServiceName;

                                if (processId > 0)
                                {
                                    if (!serviceMap.ContainsKey(processId))
                                    {
                                        serviceMap[processId] = new List<string>();
                                    }

                                    serviceMap[processId].Add(serviceName);
                                }
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(buffer);
                    }
                }
                finally
                {
                    CloseServiceHandle(scmHandle);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error gathering service information: {ex.Message}");
            }

            return serviceMap;
        }

        #endregion

        #region Display Methods

        private static void DisplayHelp()
        {
            Console.WriteLine(@"
TASKLISTAPP
This tool displays a list of currently running processes on the local machine.
For each process, the image name, process ID, and other details are displayed.

SYNTAX:
    TasklistApp [/S system [/U username [/P [password]]]]
                [/M [module] | /SVC [/SVCO] | /V]
                [/FI filter] [/FO format] [/NH]

PARAMETERS:
    /S    system           Specifies the remote system to connect to.

    /U    [domain\]user    Specifies the user context under which
                          the command should execute.

    /P    [password]       Specifies the password for the given
                          user context. Prompts for input if omitted.

    /M    [module]         Lists all tasks with DLL modules loaded
                          If module name is not specified, all loaded
                          modules are displayed.

    /SVC                   Displays services hosted in each process.
                          Shows all processes and indicates N/A for
                          processes with no associated services.

    /SVCO                  When used with /SVC, displays only processes
                          that have associated services. This filters
                          out processes with no services.

    /V                     Displays verbose task information.

    /FI   filter           Displays a set of tasks that match the
                          given criteria. Can be used multiple times.

    /FO   format           Specifies the output format.
                          Valid values: ""TABLE"", ""LIST"", ""CSV"".

    /NH                    Suppresses column headers in the output.
                          Valid only for ""TABLE"" and ""CSV"" formats.

    /?                     Displays this help message.

FILTERS:
    Filter Name     Valid Operators   Valid Value(s)
    -----------     ---------------   ----------------
    STATUS          eq, ne            RUNNING | NOT RESPONDING
    IMAGENAME       eq, ne            Image name
    PID             eq, ne, gt, lt    Process ID
    SESSION         eq, ne, gt, lt    Session number
    SESSIONNAME     eq, ne            Session name
    CPUTIME         eq, ne, gt, lt    CPU time in the format
                                     of hh:mm:ss
    MEMUSAGE        eq, ne, gt, lt    Memory usage in KB
    USERNAME        eq, ne            User name
    SERVICES        eq, ne            Service name
    WINDOWTITLE     eq, ne            Window title
    MODULES         eq, ne            DLL name

EXAMPLES:
    TasklistApp
    TasklistApp /M
    TasklistApp /SVC /FI ""PID eq 456""
    TasklistApp /V /FO CSV
    TasklistApp /SVC /FI ""SERVICES eq spooler""
    TasklistApp /FI ""USERNAME ne NT AUTHORITY\SYSTEM"" /FI ""STATUS eq running""
");
        }

        private static void DisplayProcessesWithServices(List<ProcessInfo> processes, bool onlyWithServices = false)
        {
            // Get format from parameters (if specified)
            var parameters = ParseCommandLine(Environment.GetCommandLineArgs());
            string format = "TABLE"; // Default format

            if (parameters.ContainsKey("/FO") && parameters["/FO"].Count > 0)
            {
                format = parameters["/FO"][0].ToUpper();
            }

            bool showHeaders = !parameters.ContainsKey("/NH");

            // Filter processes if needed, then sort by PID for better readability
            var displayProcesses = onlyWithServices
                ? processes.Where(p => p.Services.Count > 0).ToList()
                : processes;

            var sortedProcesses = displayProcesses.OrderBy(p => p.PID).ToList();

            //Console.WriteLine("format = " + format);
            switch (format)
            {
                case "CSV":
                    DisplayProcessesWithServicesCsv(sortedProcesses, showHeaders);
                    break;
                case "LIST":
                    DisplayProcessesWithServicesList(sortedProcesses);
                    break;
                case "TABLE":
                default:
                    DisplayProcessesWithServicesTable(sortedProcesses, showHeaders);
                    break;
            }
        }

        private static void DisplayProcessesWithServicesTable(List<ProcessInfo> processes, bool showHeaders)
        {
            // Display header
            if (showHeaders)
            {
                Console.WriteLine("\nImage Name                     PID       PPID      Services");
                Console.WriteLine("============================= ========= ========= ===============================");
            }

            foreach (var proc in processes)
            {
                if (proc.Services.Count > 0)
                {
                    // Display the first service on the same line as process info
                    Console.WriteLine($"{proc.ImageName,-30} {proc.PID,-10} {proc.PPID,-10} {proc.Services[0]}");

                    // For additional services, we print them on subsequent lines
                    for (int i = 1; i < proc.Services.Count; i++)
                    {
                        Console.WriteLine($"{"",-30} {"",-10} {"",-10} {proc.Services[i]}");
                    }
                }
                else
                {
                    // Process has no services
                    Console.WriteLine($"{proc.ImageName,-30} {proc.PID,-10} {proc.PPID,-10} N/A");
                }
            }
        }

        private static void DisplayProcessesWithServicesCsv(List<ProcessInfo> processes, bool showHeaders)
        {
            // Display header
            //if (showHeaders)
            if (true)
            {
                Console.WriteLine("Image Name,PID,PPID,Services");
            }

            foreach (var proc in processes)
            {
                // Properly escape fields that might contain commas
                string imageName = "\"" + EscapeCsvField(proc.ImageName) + "\"";
                string proc_PID = "\"" + EscapeCsvField(proc.PID.ToString()) + "\"";
                string proc_PPID = "\"" + EscapeCsvField(proc.PPID.ToString()) + "\"";

                if (proc.Services.Count > 0)
                {
                    // Combine all services into one CSV field, separated by semicolons
                    string services = string.Join("; ", proc.Services);
                    Console.WriteLine($"{imageName},B,{proc_PID},{proc_PPID},{EscapeCsvField(services)}");
                    //Console.WriteLine("I am here 1");
                }
                else
                {
                    Console.WriteLine($"{imageName},{proc_PID},{proc_PPID},N/A");
                    //Console.WriteLine("I am here 2");
                }
            }
        }

        private static void DisplayProcessesWithServicesList(List<ProcessInfo> processes)
        {
            foreach (var proc in processes)
            {
                Console.WriteLine("\n");
                Console.WriteLine($"Image Name:    {proc.ImageName}");
                Console.WriteLine($"PID:           {proc.PID}");
                Console.WriteLine($"PPID:          {proc.PPID}");

                if (proc.Services.Count > 0)
                {
                    Console.WriteLine($"Services:      {proc.Services[0]}");

                    // For additional services, we print them on subsequent lines
                    for (int i = 1; i < proc.Services.Count; i++)
                    {
                        Console.WriteLine($"               {proc.Services[i]}");
                    }
                }
                else
                {
                    Console.WriteLine("Services:      N/A");
                }
            }
        }
        

        private static void DisplayStandardProcesses(List<ProcessInfo> processes)
        {
            // Get format from parameters (if specified)
            var parameters = ParseCommandLine(Environment.GetCommandLineArgs());
            string format = "TABLE"; // Default format

            if (parameters.ContainsKey("/FO") && parameters["/FO"].Count > 0)
            {
                format = parameters["/FO"][0].ToUpper();
            }

            bool showHeaders = !parameters.ContainsKey("/NH");

            // Sort processes by PID for better readability
            var sortedProcesses = processes.OrderBy(p => p.PID).ToList();

            //Console.WriteLine("testing 800");
            //Console.WriteLine("format = " + format);

            switch (format)
            {
                case "CSV":
                    DisplayStandardProcessesCsv(sortedProcesses, showHeaders);
                    break;
                case "LIST":
                    DisplayStandardProcessesList(sortedProcesses);
                    break;
                case "TABLE":
                default:
                    DisplayStandardProcessesTable(sortedProcesses, showHeaders);
                    break;
            }
        }

        private static void DisplayStandardProcessesTable(List<ProcessInfo> processes, bool showHeaders)
        {
            // Display header
            if (showHeaders)
            {
                Console.WriteLine("\nImage Name                     PID       PPID      Session Name        Session#    Mem Usage");
                Console.WriteLine("============================= ========= ========= ================ =========== ============");
            }

            foreach (var proc in processes)
            {
                Console.WriteLine($"{proc.ImageName,-30} {proc.PID,-10} {proc.PPID,-10} {proc.SessionName,-17} {proc.SessionId,-12} {proc.MemUsage}");
            }
        }

        private static void DisplayStandardProcessesCsv(List<ProcessInfo> processes, bool showHeaders)
        {
            // Display header
            if (showHeaders)
            {
                Console.WriteLine("Image Name,PID,PPID,Session Name,Session#,Mem Usage");
            }

            foreach (var proc in processes)
            {
                // Properly escape fields that might contain commas
                string imageName = EscapeCsvField(proc.ImageName);
                string sessionName = EscapeCsvField(proc.SessionName ?? "");

                Console.WriteLine($"{imageName},{proc.PID},{proc.PPID},{sessionName},{proc.SessionId},{EscapeCsvField(proc.MemUsage)}");
            }
        }

        private static void DisplayStandardProcessesList(List<ProcessInfo> processes)
        {
            foreach (var proc in processes)
            {
                Console.WriteLine("\n");
                Console.WriteLine($"Image Name:    {proc.ImageName}");
                Console.WriteLine($"PID:           {proc.PID}");
                Console.WriteLine($"PPID:          {proc.PPID}");
                Console.WriteLine($"Session Name:  {proc.SessionName ?? ""}");
                Console.WriteLine($"Session#:      {proc.SessionId}");
                Console.WriteLine($"Mem Usage:     {proc.MemUsage}");
            }
        }

        private static string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field))
                return "";

            // If the field contains comma, newline, or double-quote, escape it
            if (field.Contains(",") || field.Contains("\"") || field.Contains("\n") || field.Contains("\r"))
            {
                // Replace double quotes with two double quotes
                field = field.Replace("\"", "\"\"");
                // Wrap in quotes
                return $"\"{field}\"";
            }

            return field;
        }

        private static void DisplayVerboseProcesses(List<ProcessInfo> processes)
        {
            // Get format from parameters (if specified)
            var parameters = ParseCommandLine(Environment.GetCommandLineArgs());
            string format = "TABLE"; // Default format

            if (parameters.ContainsKey("/FO") && parameters["/FO"].Count > 0)
            {
                format = parameters["/FO"][0].ToUpper();
            }

            bool showHeaders = !parameters.ContainsKey("/NH");

            // Sort processes by PID for better readability
            var sortedProcesses = processes.OrderBy(p => p.PID).ToList();

            switch (format)
            {
                case "CSV":
                    DisplayVerboseProcessesCsv(sortedProcesses, showHeaders);
                    break;
                case "LIST":
                    DisplayVerboseProcessesList(sortedProcesses);
                    break;
                case "TABLE":
                default:
                    DisplayVerboseProcessesTable(sortedProcesses, showHeaders);
                    break;
            }
        }

        private static void DisplayVerboseProcessesTable(List<ProcessInfo> processes, bool showHeaders)
        {
            // Display header
            if (showHeaders)
            {
                Console.WriteLine("\nImage Name                     PID       PPID      Session Name     Session# Mem Usage Status          Username                 Window Title");
                Console.WriteLine("============================= ========= ========= ================ ======= ========= =============== ======================== ================================");
            }

            foreach (var proc in processes)
            {
                Console.WriteLine($"{proc.ImageName,-30} {proc.PID,-10} {proc.PPID,-10} {proc.SessionName,-17} {proc.SessionId,-8} {proc.MemUsage,-10} {proc.Status,-16} {proc.Username,-25} {proc.WindowTitle}");
            }
        }

        private static void DisplayVerboseProcessesCsv(List<ProcessInfo> processes, bool showHeaders)
        {
            // Display header
            if (showHeaders)
            {
                Console.WriteLine("Image Name,PID,PPID,Session Name,Session#,Mem Usage,Status,Username,Window Title");
            }

            foreach (var proc in processes)
            {
                // Properly escape fields that might contain commas
                string imageName = "\"" + EscapeCsvField(proc.ImageName) + "\"";
                string sessionName = "\"" + EscapeCsvField(proc.SessionName ?? "") + "\"";
                string status = "\"" + EscapeCsvField(proc.Status ?? "") + "\"";
                string username = "\"" + EscapeCsvField(proc.Username ?? "") + "\"";
                string windowTitle = "\"" + EscapeCsvField(proc.WindowTitle ?? "") + "\"";
                string proc_PID = "\"" + proc.PID + "\"";
                string proc_PPID = "\"" + proc.PPID + "\"";
                string proc_sessionid = "\"" + proc.SessionId + "\"";
                string proc_MemUsage = "\"" + EscapeCsvField(proc.MemUsage) + "\"";

                Console.WriteLine($"{imageName},{proc_PID},{proc_PPID},{sessionName},{proc_sessionid},{proc_MemUsage},{status},{username},{windowTitle}");
            }
        }

        private static void DisplayVerboseProcessesList(List<ProcessInfo> processes)
        {
            foreach (var proc in processes)
            {
                Console.WriteLine("\n");
                Console.WriteLine($"Image Name:    {proc.ImageName}");
                Console.WriteLine($"PID:           {proc.PID}");
                Console.WriteLine($"PPID:          {proc.PPID}");
                Console.WriteLine($"Session Name:  {proc.SessionName ?? ""}");
                Console.WriteLine($"Session#:      {proc.SessionId}");
                Console.WriteLine($"Mem Usage:     {proc.MemUsage}");
                Console.WriteLine($"Status:        {proc.Status ?? ""}");
                Console.WriteLine($"Username:      {proc.Username ?? ""}");
                Console.WriteLine($"Window Title:  {proc.WindowTitle ?? ""}");
            }
        }

        private static void DisplayProcessesWithModules(List<ProcessInfo> processes, string moduleFilter)
        {
            // This method would implement the /M parameter functionality
            // It would need to get module information for each process and display it
            Console.WriteLine("Module display not fully implemented yet.");
        }

        #endregion

        #region Filtering

        private static List<ProcessInfo> ApplyFilter(List<ProcessInfo> processes, string filterExpression)
        {
            // Parse the filter expression (format is "FILTERTYPE eq FILTERVALUE")
            string[] parts = filterExpression.Split(new[] { ' ' }, 3);

            if (parts.Length < 3)
            {
                Console.Error.WriteLine($"Invalid filter format: {filterExpression}");
                return processes;
            }

            string filterType = parts[0].ToUpper();
            string operatorStr = parts[1].ToUpper();
            string filterValue = parts[2];

            // Implement filtering based on different types and operators
            switch (filterType)
            {
                case "IMAGENAME":
                    return FilterByImageName(processes, operatorStr, filterValue);
                case "PID":
                    return FilterByPid(processes, operatorStr, filterValue);
                case "SERVICES":
                    return FilterByServices(processes, operatorStr, filterValue);
                case "MEMUSAGE":
                    return FilterByMemUsage(processes, operatorStr, filterValue);
                default:
                    Console.Error.WriteLine($"Unsupported filter type: {filterType}");
                    return processes;
            }
        }

        private static List<ProcessInfo> FilterByImageName(List<ProcessInfo> processes, string operatorStr, string filterValue)
        {
            switch (operatorStr)
            {
                case "EQ":
                    return processes.Where(p => string.Equals(p.ImageName, filterValue, StringComparison.OrdinalIgnoreCase)).ToList();
                case "NE":
                    return processes.Where(p => !string.Equals(p.ImageName, filterValue, StringComparison.OrdinalIgnoreCase)).ToList();
                case "GT":
                    return processes.Where(p => string.Compare(p.ImageName, filterValue, StringComparison.OrdinalIgnoreCase) > 0).ToList();
                case "LT":
                    return processes.Where(p => string.Compare(p.ImageName, filterValue, StringComparison.OrdinalIgnoreCase) < 0).ToList();
                default:
                    Console.Error.WriteLine($"Unsupported operator for IMAGENAME: {operatorStr}");
                    return processes;
            }
        }

        private static List<ProcessInfo> FilterByPid(List<ProcessInfo> processes, string operatorStr, string filterValue)
        {
            if (int.TryParse(filterValue, out int pidValue))
            {
                switch (operatorStr)
                {
                    case "EQ":
                        return processes.Where(p => p.PID == pidValue).ToList();
                    case "NE":
                        return processes.Where(p => p.PID != pidValue).ToList();
                    case "GT":
                        return processes.Where(p => p.PID > pidValue).ToList();
                    case "LT":
                        return processes.Where(p => p.PID < pidValue).ToList();
                    default:
                        Console.Error.WriteLine($"Unsupported operator for PID: {operatorStr}");
                        return processes;
                }
            }

            Console.Error.WriteLine($"Invalid PID value: {filterValue}");
            return processes;
        }

        private static List<ProcessInfo> FilterByServices(List<ProcessInfo> processes, string operatorStr, string filterValue)
        {
            switch (operatorStr)
            {
                case "EQ":
                    return processes.Where(p => p.Services.Any(s => string.Equals(s, filterValue, StringComparison.OrdinalIgnoreCase))).ToList();
                case "NE":
                    return processes.Where(p => !p.Services.Any(s => string.Equals(s, filterValue, StringComparison.OrdinalIgnoreCase))).ToList();
                default:
                    Console.Error.WriteLine($"Unsupported operator for SERVICES: {operatorStr}");
                    return processes;
            }
        }

        private static List<ProcessInfo> FilterByMemUsage(List<ProcessInfo> processes, string operatorStr, string filterValue)
        {
            // Parse memory value with KB, MB, etc.
            long memoryBytes = ParseMemoryString(filterValue);

            if (memoryBytes >= 0)
            {
                switch (operatorStr)
                {
                    case "EQ":
                        return processes.Where(p => ParseMemoryString(p.MemUsage) == memoryBytes).ToList();
                    case "NE":
                        return processes.Where(p => ParseMemoryString(p.MemUsage) != memoryBytes).ToList();
                    case "GT":
                        return processes.Where(p => ParseMemoryString(p.MemUsage) > memoryBytes).ToList();
                    case "LT":
                        return processes.Where(p => ParseMemoryString(p.MemUsage) < memoryBytes).ToList();
                    default:
                        Console.Error.WriteLine($"Unsupported operator for MEMUSAGE: {operatorStr}");
                        return processes;
                }
            }

            Console.Error.WriteLine($"Invalid memory usage value: {filterValue}");
            return processes;
        }

        #endregion

        #region Utility Methods

        private static string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int counter = 0;
            decimal number = bytes;

            while (Math.Round(number / 1024) >= 1)
            {
                number /= 1024;
                counter++;
            }

            return $"{number:n0} {suffixes[counter]}";
        }

        private static long ParseMemoryString(string memoryString)
        {
            try
            {
                Regex regex = new Regex(@"^(\d+)\s*([KMGT]B|B)?$", RegexOptions.IgnoreCase);
                Match match = regex.Match(memoryString);

                if (match.Success)
                {
                    long value = long.Parse(match.Groups[1].Value);
                    string unit = match.Groups[2].Value.ToUpper();

                    switch (unit)
                    {
                        case "B":
                            return value;
                        case "KB":
                            return value * 1024;
                        case "MB":
                            return value * 1024 * 1024;
                        case "GB":
                            return value * 1024 * 1024 * 1024;
                        case "TB":
                            return value * 1024 * 1024 * 1024 * 1024;
                        default:
                            return value; // Assume bytes if no unit specified
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error parsing memory string: {ex.Message}");
            }

            return -1; // Invalid format
        }

        #endregion
    }
}