/***********************************************************
 * Robert Schwartz
 * DFOR 740
 * Spring 2025
 * RobsTaskKill Program
 ***********************************************************/
using System;
using System.Diagnostics;
using System.Collections.Generic;

namespace RemoteTaskKill
{
    class Program
    {
        static void Main(string[] args)
        {
            // Define command-line parameters
            string processName = string.Empty;
            int? processId = null;
            string remoteComputer = string.Empty;
            string username = string.Empty;
            string password = string.Empty;
            bool force = false;
            bool tree = false;

            // Parse command-line arguments
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i].ToLower();

                switch (arg)
                {
                    case "/im":
                        // Process name parameter
                        if (i + 1 < args.Length)
                        {
                            processName = args[++i];
                        }
                        break;

                    case "/pid":
                        // Process ID parameter
                        if (i + 1 < args.Length && int.TryParse(args[++i], out int pid))
                        {
                            processId = pid;
                        }
                        break;

                    case "/f":
                        // Force termination parameter
                        force = true;
                        break;

                    case "/t":
                        // Terminate process tree parameter
                        tree = true;
                        break;

                    case "/s":
                        // Remote computer parameter
                        if (i + 1 < args.Length)
                        {
                            remoteComputer = args[++i];
                        }
                        break;

                    case "/u":
                        // Username parameter for remote computer
                        if (i + 1 < args.Length)
                        {
                            username = args[++i];
                        }
                        break;

                    case "/p":
                        // Password parameter for remote computer
                        if (i + 1 < args.Length)
                        {
                            password = args[++i];
                        }
                        break;

                    case "/?":
                    case "/help":
                        DisplayHelp();
                        return;
                }
            }

            // Validate parameters
            if (string.IsNullOrEmpty(processName) && !processId.HasValue)
            {
                Console.WriteLine("ERROR: No process specified. Specify a process name or ID.");
                DisplayHelp();
                return;
            }

            // If remote computer is specified, validate remote authentication
            if (!string.IsNullOrEmpty(remoteComputer))
            {
                // Username is required for remote connections
                if (string.IsNullOrEmpty(username))
                {
                    Console.WriteLine("ERROR: Username (/U) is required when specifying a remote computer.");
                    return;
                }
            }

            try
            {
                // Build the taskkill command
                string arguments = BuildTaskKillCommand(processName, processId, remoteComputer,
                                                        username, password, force, tree);

                // Execute the taskkill command
                ExecuteTaskKill(arguments);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
            }
        }

        static string BuildTaskKillCommand(string processName, int? processId, string remoteComputer,
                                          string username, string password, bool force, bool tree)
        {
            List<string> arguments = new List<string>();

            // Add remote computer parameter if specified
            if (!string.IsNullOrEmpty(remoteComputer))
            {
                arguments.Add($"/S {remoteComputer}");
            }

            // Add username parameter if specified
            if (!string.IsNullOrEmpty(username))
            {
                arguments.Add($"/U {username}");
            }

            // Add password parameter if specified
            if (!string.IsNullOrEmpty(password))
            {
                arguments.Add($"/P {password}");
            }

            // Add process identifier (by name or ID)
            if (!string.IsNullOrEmpty(processName))
            {
                arguments.Add($"/IM {processName}");
            }
            else if (processId.HasValue)
            {
                arguments.Add($"/PID {processId.Value}");
            }

            // Add force parameter if specified
            if (force)
            {
                arguments.Add("/F");
            }

            // Add tree parameter if specified
            if (tree)
            {
                arguments.Add("/T");
            }

            return string.Join(" ", arguments);
        }

        static void ExecuteTaskKill(string arguments)
        {
            // Create process start info
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "taskkill",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            // Start the process
            using (Process process = new Process { StartInfo = psi })
            {
                process.Start();

                // Read and display output
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                // Display results
                if (!string.IsNullOrEmpty(output))
                {
                    Console.WriteLine(output);
                }

                if (!string.IsNullOrEmpty(error))
                {
                    Console.WriteLine(error);
                }

                // Check exit code
                if (process.ExitCode != 0)
                {
                    Console.WriteLine($"TaskKill exited with code {process.ExitCode}");
                }
            }
        }

        static void DisplayHelp()
        {
            Console.WriteLine("Remote TaskKill - Terminates processes on local or remote systems");
            Console.WriteLine("\nSYNTAX:");
            Console.WriteLine("  RemoteTaskKill [/S system] [/U username] [/P password]");
            Console.WriteLine("               {[/PID processid] | [/IM imagename]} [/F] [/T]");
            Console.WriteLine("\nPARAMETERS:");
            Console.WriteLine("  /S    system        Specifies the remote system to connect to");
            Console.WriteLine("  /U    username      Specifies the user context to execute the command");
            Console.WriteLine("  /P    password      Specifies the password for the given user context");
            Console.WriteLine("  /PID  processid     Specifies the PID of the process to terminate");
            Console.WriteLine("  /IM   imagename     Specifies the image name of the process to terminate");
            Console.WriteLine("  /F                  Forces termination of processes");
            Console.WriteLine("  /T                  Terminates the specified process and any child processes");
            Console.WriteLine("  /?                  Displays this help message");
            Console.WriteLine("\nEXAMPLES:");
            Console.WriteLine("  RemoteTaskKill /IM notepad.exe");
            Console.WriteLine("  RemoteTaskKill /PID 1234 /F");
            Console.WriteLine("  RemoteTaskKill /S remotesystem /U domain\\user /P password /IM notepad.exe");
        }
    }
}