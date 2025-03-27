# DFOR-740-Midterm
This is my Midterm projects for DFOR 740 - I did the tasklist / taskkill
Robert Schwartz
DFOR 740 Spring 2025

There are a few differences between the orginal tasklist and my version:
1) I wanted the parent PID done to be shown always
2) I did not how /svc showed a lot of extra garbage, so I created a secondary flag (/svco) which will show only the programs that are using services

Note: to run the program, you four files:
            TasklistCSV.exe
            TasklistCSV.dll
            TasklistCSV.deps.json
            TasklistCSV.runtimeconfig.json
I chose to name it differently to ensure when testing I could if the real tasklist was running or was it my program that was running

I did use Claude to help me with this program.

# TasklistApp

## Overview
TasklistApp is a command-line utility that displays information about currently running processes on a Windows system. It serves as a cross-platform alternative to the Windows built-in `tasklist` command, providing similar functionality with enhanced performance by using direct Win32 API calls instead of WMI queries.

## Features
- Lists all running processes with their associated information (PID, memory usage, etc.)
- Displays services associated with processes
- Filters processes based on various criteria
- Supports multiple output formats (Table, List, CSV)
- Provides detailed information about processes in verbose mode
- Low overhead implementation using native Windows API calls

## System Requirements
- Windows operating system
- .NET Framework 4.5 or higher

## Usage Syntax
```
TasklistApp [/S system [/U username [/P [password]]]]
            [/M [module] | /SVC [/SVCO] | /V]
            [/FI filter] [/FO format] [/NH]
```

## Parameters
- `/S system`: Specifies the remote system to connect to.
- `/U [domain\]user`: Specifies the user context under which the command should execute.
- `/P [password]`: Specifies the password for the given user context. Prompts for input if omitted.
- `/M [module]`: Lists all tasks with DLL modules loaded. If module name is not specified, all loaded modules are displayed.
- `/SVC`: Displays services hosted in each process.
- `/SVCO`: When used with /SVC, displays only processes that have associated services.
- `/V`: Displays verbose task information.
- `/FI filter`: Displays a set of tasks that match the given criteria. Can be used multiple times.
- `/FO format`: Specifies the output format. Valid values: "TABLE", "LIST", "CSV".
- `/NH`: Suppresses column headers in the output. Valid only for "TABLE" and "CSV" formats.
- `/?`: Displays help information.

## Filters
TasklistApp supports filtering processes based on various criteria:
```
Filter Name     Valid Operators   Valid Value(s)
-----------     ---------------   ----------------
STATUS          eq, ne            RUNNING | NOT RESPONDING
IMAGENAME       eq, ne            Image name
PID             eq, ne, gt, lt    Process ID
SESSION         eq, ne, gt, lt    Session number
SESSIONNAME     eq, ne            Session name
CPUTIME         eq, ne, gt, lt    CPU time in format hh:mm:ss
MEMUSAGE        eq, ne, gt, lt    Memory usage in KB
USERNAME        eq, ne            User name
SERVICES        eq, ne            Service name
WINDOWTITLE     eq, ne            Window title
MODULES         eq, ne            DLL name
```

## Examples
```
TasklistApp
TasklistApp /M
TasklistApp /SVC /FI "PID eq 456"
TasklistApp /V /FO CSV
TasklistApp /SVC /FI "SERVICES eq spooler"
TasklistApp /FI "USERNAME ne NT AUTHORITY\SYSTEM" /FI "STATUS eq running"
```

## Implementation Details
TasklistApp uses direct Windows API calls to gather process information rather than WMI queries, resulting in faster execution and lower system resource usage. The application uses the following Windows APIs:
- Win32 Process APIs
- Windows Terminal Services APIs
- Windows Service Control Manager APIs
- NT Native APIs

The application is implemented in C# and uses the .NET Framework.

## Limitations
- Some features like module information display are not fully implemented.
- Remote system querying may require appropriate permissions.
- Certain process information may be limited based on user permissions.

## Troubleshooting
- If you encounter permission errors, try running the application with administrator privileges.
- For remote system connections, ensure the appropriate firewall settings are configured.
- Check that the specified filters use the correct syntax and value formats.

## License
This software is provided as-is with no explicit warranty. Use at your own risk.
