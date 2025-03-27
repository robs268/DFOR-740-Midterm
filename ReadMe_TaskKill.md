# TaskKillRobs
# Robert Schwartz
# DFOR 740 Spring 2025

I chose to change the name so that I could tell the difference when running the original (taskkill) and mine(TaskKillRobs).

A C# command-line utility that provides an enhanced interface to the Windows `taskkill` command, allowing users to terminate processes on both local and remote systems.

## Description

TaskKillRobs extends the functionality of the built-in Windows `taskkill` command by providing a more user-friendly interface with improved parameter handling and error reporting. It allows system administrators and power users to terminate processes running on local or remote Windows systems using either process names or process IDs.

## Features

- Terminate processes by image name or process ID
- Connect to remote systems to terminate processes
- Authenticate with remote systems using username and password
- Force termination of processes that don't respond to standard termination signals
- Terminate process trees (a process and all its child processes)
- Detailed help information and usage examples

## Prerequisites

- Windows operating system
- .NET Framework or .NET Core runtime
- Appropriate permissions to terminate processes
- For remote operations: network access and administrative privileges on the target system

## Installation

1. Clone this repository or download the source code
2. Build the solution using Visual Studio or the .NET CLI:
   ```
   dotnet build
   ```
3. The executable will be created in the build output directory

## Usage

```
TaskKillRobs [/S system] [/U username] [/P password]
               {[/PID processid] | [/IM imagename]} [/F] [/T]
```

### Parameters

- `/S system` - Specifies the remote system to connect to
- `/U username` - Specifies the user context to execute the command
- `/P password` - Specifies the password for the given user context
- `/PID processid` - Specifies the PID of the process to terminate
- `/IM imagename` - Specifies the image name of the process to terminate
- `/F` - Forces termination of processes
- `/T` - Terminates the specified process and any child processes
- `/?` or `/help` - Displays help information

### Examples

Terminate Notepad on the local system:
```
TaskKillRobs /IM notepad.exe
```

Forcefully terminate a process with PID 1234:
```
TaskKillRobs /PID 1234 /F
```

Terminate Notepad on a remote system with authentication:
```
TaskKillRobs /S remotesystem /U domain\user /P password /IM notepad.exe
```

Terminate a process and all its child processes:
```
TaskKillRobs /IM chrome.exe /T
```

## Security Considerations

- Storing passwords in command-line arguments is not secure for production environments
- Consider using Windows authentication or more secure credential management for sensitive environments
- Remote process termination should be restricted to authorized administrators

## How It Works

RemoteTaskKill is a wrapper around the Windows `taskkill` command. It:

1. Parses and validates command-line arguments
2. Builds the appropriate `taskkill` command
3. Executes the command and captures its output
4. Displays the results to the user with improved formatting

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Free

## Acknowledgements

This utility is based on the Windows `taskkill` command-line tool functionality.
