<?php
//error_reporting(E_ALL & ~E_WARNING & ~E_NOTICE);

// Start output buffering
ob_start();

function isValidWindowsPath($path) {
    // Remove extra backslashes and trim
    $path = trim(preg_replace('/\\\\+/', '\\', $path));

    // Debugging output
    //echo "Sanitized path: " . htmlspecialchars($path) . "<br>";

    // Ensure the path does not contain invalid characters
    $invalidChars = ['<', '>', '"', '|', '?', '*'];  // Removed ':' from invalid chars
    foreach ($invalidChars as $char) {
        if (strpos($path, $char) !== false) {
            return false;
        }
    }

    // Check if the path starts with a drive letter (e.g., C:)
    if (!preg_match('#^[a-zA-Z]:\\\\#i', $path)) {
        return false;
    }

    return $path;
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Clear any previous output
    ob_clean();
    
    $auditFileName = $_POST['audit_file_name'] ?? 'audit';
    $customPaths = $_POST['custom_paths'] ?? [];

    // Validate audit file name
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $auditFileName)) {
        die("Invalid audit file name. Only alphanumeric characters, underscores, and dashes are allowed.");
    }

    // Validate and sanitize custom paths
    foreach ($customPaths as &$path) {
        $path = isValidWindowsPath($path);
        if (!$path) {
            die("Invalid path detected: " . htmlspecialchars($path));
        }
    }
    unset($path);

    // Generate audit file content
    $today = date('Y-m-d'); // Get the current date
    $content = "";

    // Part 1
    $content .= <<<EOT
<check_type:"Windows">

# Windows Security Audit Checks
# Last updated: {$today}

<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "01.0 Check environment variables and shell settings"
    cmd            : "Get-ChildItem Env: | Format-Table -AutoSize"
    info           : "Review the environment variables to ensure no sensitive or misconfigured variables exist that could lead to security vulnerabilities."
</custom_item>


<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "02.0 Check which processes are running as SYSTEM"
    cmd            : "Get-Process | Where-Object {\$_.Handles -gt 0} | Format-Table Id, ProcessName, Handles, StartInfo"
    info           : "Review processes running with elevated SYSTEM privileges to identify any unnecessary or risky services."
</custom_item>


<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "03.0 Check installed applications and versions"
    cmd            : "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize"
    info           : "Review installed applications to ensure only necessary and up-to-date software is running."
</custom_item>


<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "04.0 Check scheduled tasks"
    cmd            : "Get-ScheduledTask | Format-Table TaskName, TaskPath, State"
    info           : "Ensure no unauthorized or malicious scheduled tasks are running."
</custom_item>

EOT;

    // Part 2
    $counter = 0;
    foreach ($customPaths as $index => $path) {
        $content .= <<<EOT

<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "05.{$counter}.0 Search for sensitive data in folder {$path}"
    cmd            : "Select-String -Path '{$path}' -Pattern 'password|api_key|token|username|secret|key|auth|pass|pwd'"
    info           : "Search for potentially exposed sensitive data in configuration files. Adjust the path to match your configuration file directory."
</custom_item>

EOT;
        $counter++;
    }

    // Part 3
    $content .= <<<EOT

<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "06.0 Check user privileges"
    cmd            : "Get-LocalUser | Select-Object Name, Enabled, Description"
    info           : "Review local users and ensure only authorized accounts are enabled."
</custom_item>


<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "07.0 Check command history"
    cmd            : "Get-Content `\"$`env:APPDATA\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt`\""
    info           : "Examine PowerShell command history for sensitive data or suspicious commands."
</custom_item>

<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "08.0 Check files with special permissions on all attached drives"
    cmd            : "Get-PSDrive -PSProvider FileSystem | ForEach-Object { icacls ($_.Root + '*') | Findstr 'Everyone' }"
    info           : "Review files with permissions granted to 'Everyone' across all attached drives for potential security risks."
</custom_item>


<custom_item>
    system          : "Windows"
    type           : CMD_EXEC
    description    : "09.0 Check log rotation"
    cmd            : "wevtutil el | ForEach-Object {wevtutil gl $_ | Select-String -Pattern 'Retention'}"
    info           : "Verify log retention policies for Windows Event Logs."
</custom_item>

<custom_item>
		type: AUDIT_POWERSHELL
		description: "10.0 Show installed application - Crowdstrike EDR"
		value_type: POLICY_TEXT
		value_data: ""
		powershell_args: "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | findstr CrowdStrike"
		only_show_cmd_output: YES
</custom_item>

<custom_item>
		type: AUDIT_POWERSHELL
		description: "11. Show installed application - Devo SIEM Agent"
		value_type: POLICY_TEXT
		value_data: ""
		powershell_args: "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | findstr osquery"
		only_show_cmd_output: YES
</custom_item>



</check_type:"Windows">
EOT;

    // Serve the file as a download
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="' . $auditFileName . '.audit"');
    echo $content;
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custom PrivCheck Audit File Generator (Windows)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-lg-8 col-md-10">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                    <h3 class="card-title mb-0" style="color: white;">Windows PrivCheck Audit File Generator (<a href="index.php" style="color: white;">Unix</a> | <a href="windows.php" style="color: white;">Windows</a>)</h3>

                    </div>
                    <div class="card-body">
                        <form method="POST" id="auditForm">
                            <!-- Audit File Name -->
                            <div class="mb-4">
                                <label for="audit_file_name" class="form-label fw-semibold">Audit File Name</label>
                                <input type="text" class="form-control" id="audit_file_name" name="audit_file_name" 
                                       placeholder="Enter a name for your audit file, e.g. CR Number" required>
                                <div class="form-text">Use only alphanumeric characters, underscores, or dashes.</div>
                            </div>

                            <!-- Dynamic Custom Paths -->
                            <div id="customPathsContainer" class="mb-4">
                                <label class="form-label fw-semibold">Custom Paths</label>
                                <div class="input-group mb-2">
                                    <input type="text" class="form-control" name="custom_paths[]" 
                                           placeholder="Enter a valid Unix directory path" required>
                                    <button type="button" class="btn btn-danger" onclick="removePath(this)">
                                        Remove
                                    </button>
                                </div>
                            </div>
                            <button type="button" class="btn btn-secondary mb-3" onclick="addPath()">
                                Add Another Path
                            </button>

                            <!-- Submit Button -->
                            <div class="text-center">
                                <button type="submit" class="btn btn-primary w-100">
                                    Generate Audit File
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function addPath() {
            const container = document.getElementById('customPathsContainer');
            const div = document.createElement('div');
            div.classList.add('input-group', 'mb-2');

            div.innerHTML = `
                <input type="text" class="form-control" name="custom_paths[]" 
                       placeholder="Enter a valid Unix directory path" required>
                <button type="button" class="btn btn-danger" onclick="removePath(this)">Remove</button>
            `;

            container.appendChild(div);
        }

        function removePath(button) {
            button.parentElement.remove();
        }
    </script>
</body>
</html>

