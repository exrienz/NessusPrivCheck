<?php
// Helper function to validate Unix directory paths
function isValidPath($path) {
    // Validate that the path contains only allowed characters (alphanumeric, /, ., -, _)
    return preg_match('/^[a-zA-Z0-9\/._-]+$/', $path);
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $auditFileName = $_POST['audit_file_name'] ?? 'audit';
    $customPaths = $_POST['custom_paths'] ?? [];

    // Validate audit file name
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $auditFileName)) {
        die("Invalid audit file name. Only alphanumeric characters, underscores, and dashes are allowed.");
    }

    // Validate and sanitize custom paths
    foreach ($customPaths as &$path) {
        // Ensure the path starts with a "/"
        if (substr($path, 0, 1) !== '/') {
            $path = '/' . $path;
        }
        
        // Ensure the path ends with a "/"
        if (substr($path, -1) !== '/') {
            $path .= '/';
        }
        
        // Validate the path
        if (!isValidPath($path)) {
            die("Invalid path detected: " . htmlspecialchars($path));
        }
    }
    // Unset the reference to avoid potential side effects
    unset($path);


    // Generate audit file content
    $today = date('Y-m-d'); // Get the current date
    $content = "";

    // Part 1
    $content .= <<<EOT
<check_type:"Unix">

# Linux Security Audit Checks
# Last updated: {$today}

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "01.0 Check environment variables and shell settings"
    cmd            : "env ; set"
    info           : "Review the output of 'env' and 'set' commands to verify that no sensitive or misconfigured environment variables exist that could lead to security vulnerabilities."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "02.0 Check which services are running as root"
    cmd            : "ps aux | grep root && ps -ef | grep root"
    info           : "Examine the output of 'ps aux' and 'ps -ef' commands to identify any unnecessary services running with root privileges that could pose a security risk."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "03.0 Check installed applications and versions"
    cmd            : "ls -alh /usr/bin/ && ls -alh /sbin/ && rpm -qa && ls -alh /var/cache/yum/"
    info           : "Review the list of installed applications and versions to ensure that only necessary and up-to-date software is running."
</custom_item>

<custom_item>
    system          : "Linux"
    type            : CMD_EXEC
    description     : "04.0 Check service configurations"
    cmd             : "find / -type f \( -iname 'httpd.conf' -o -iname 'server.xml' -o -iname '*.conf' -o -iname '*.properties' -o -iname '*.xml' -o -iname '*nginx*.conf' -o -iname '*web*.conf' -o -iname '*jboss*.xml' -o -iname '*tomcat*.xml' -o -iname '*jetty*.xml' -o -iname '*glassfish*.xml' -o -iname '*iis*.config' \) -exec cat {} \; 2>/dev/null && find /etc /var /opt /usr /home -type f \( -iname '*.conf' -o -iname '*.xml' -o -iname '*.properties' \) -exec ls -al {} \; && ls -aRl /etc/ | awk '$1 ~ /^.*r.*/'"
    info            : "Recursively search all paths for web server configuration files (Apache, Nginx, Tomcat, JBoss, Jetty, IIS, etc.) starting from root. Identify potential misconfigurations that could expose the system to vulnerabilities."
</custom_item>


<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "05.0 Check scheduled jobs"
    cmd            : "crontab -l && ls -alh /var/spool/cron && ls -al /etc/ | grep cron && ls -al /etc/cron* && cat /etc/cron* && cat /etc/at.allow && cat /etc/at.deny && cat /etc/cron.allow && cat /etc/cron.deny && cat /etc/crontab && cat /etc/anacrontab && cat /var/spool/cron/crontabs/root"
    info           : "Ensure that no unauthorized or malicious scheduled jobs are running."
</custom_item>
EOT;

    // Part 2
    $counter = 0;
    foreach ($customPaths as $index => $path) {
        $content .= <<<EOT

<custom_item>
    system      : "Linux"
    type        : CMD_EXEC
    description : "06.{$counter}.0 Search for sensitive data in configuration files in folder {$path}"
    cmd         : "find {$path} -type f -exec grep -iE 'password|api_key|token|username|secret|key|db_password|auth|pass|pwd' {} +"
    info        : "Search for potentially exposed sensitive data in configuration files."
</custom_item>
EOT;
        $counter++;
    }

    // Part 3
    $content .= <<<EOT

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "07.0. Check home directories"
    cmd            : "ls -ahlR /root/ && ls -ahlR /home/"
    info           : "Review all files in /root/ and /home/ to ensure no sensitive files are exposed."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "08.0. Check user privileges"
    cmd            : "cat /etc/passwd | cut -d: -f1 && grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0 { print $1}' && awk -F: '($3 == \"0\") {print}' /etc/passwd && cat /etc/sudoers && sudo -l"
    info           : "Review user privileges and sudo access rights."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "09.0. Check command history"
    cmd            : "cat ~/.bash_history && cat ~/.nano_history && cat ~/.atftp_history && cat ~/.mysql_history && cat /opt/tomcat/logs/catalina.out && cat /opt/jboss/server/logs/standalone.log"
    info           : "Examine command history and logs for sensitive data or suspicious commands."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "10.0. Check writable configuration files"
    cmd            : "ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null && find /etc/ -readable -type f 2>/dev/null && find /etc/ -readable -type f -maxdepth 1 2>/dev/null"
    info           : "Review writable and readable files in /etc/ for potential security risks."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "11.0. Check world-writeable files"
    cmd            : "find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print && find / -xdev \( -nouser -o -nogroup \) -print"
    info           : "Identify world-writeable and ownerless files that may pose security risks."
</custom_item>

<custom_item>
    system      : "Linux"
    type        : CMD_EXEC
    description : "12.0. Check file permissions in /etc/"
    cmd         : "find /etc/ -type f -perm -0002 -exec ls -l {} +" 
    info        : "Review world-writable files in /etc/ for potential security vulnerabilities."
</custom_item>

<custom_item>
    system      : "Linux"
    type        : CMD_EXEC
    description : "13.0. Check SUID/SGID Files"
    cmd         : "find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;" 
    info        : "Review files with SUID/SGID bits set for potential security risks."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "14.0. Check log rotation"
    cmd            : "grep -q 'weekly' /etc/logrotate.conf && ls /etc/logrotate.d/ && find /var/log/ -type f -name '*.1' -or -name '*.2' | wc -l"
    info           : "Verify log rotation configuration and implementation."
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "15.0. Check SIEM Agent"
    cmd            : "/opt/osquery/bin/osqueryctl status"
    info           : "Verify osquery agent installation and status."
    expect         : "^[\s]*osqueryd.*running[\s]*"
    solution       : "Install osquery agent if missing"
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "16.0. Check EDR Status"
    cmd            : "/usr/bin/ps -e | grep falcon-sensor"
    info           : "Verify Crowdstrike Falcon installation and status."
    expect         : ".*falcon-sensor.*"
    solution       : "Install Crowdstrike Falcon if missing"
</custom_item>

<custom_item>
    system          : "Linux"
    type           : CMD_EXEC
    description    : "17.0. Verify hostname convention"
    cmd            : "/bin/hostname"
    info           : "Verify hostname follows naming convention."
    expect         : "^[vp](?:cbj|bgr)(?:inf|rpp|its|slbt|rpphap|fpx|dda|dwh|ecm|fir|ibg|ddt|jom).*0[1-9][pus]$"
    solution       : "Update hostname to match required convention"
</custom_item>

<custom_item>
  type                : FILE_CONTENT_CHECK
  description         : "18.0 Ensure no untrusted certificates are installed"
  file                : "/etc/ssl/certs/"
  regex               : ".*"
  expect              : ""
  info                : "Checks all certificate files in /etc/ssl/certs for review by IT security. No specific assumptions about untrusted certificates."
  solution            : "IT security should manually review all certificates in /etc/ssl/certs/ to identify untrusted certificates."
</custom_item>

<custom_item>
  type                : CMD_EXEC
  description         : "19.0 Verify CA certificates are from trusted sources"
  command             : "openssl verify -CAfile /etc/ssl/certs/ca-bundle.crt /etc/ssl/certs/*.crt"
  expect              : ""
  info                : "Runs the openssl verify command to check the validity of all certificates. IT security should manually review the output for certificates from untrusted sources."
  solution            : "Replace any CA certificates that are invalid or from untrusted sources after manual verification."
</custom_item>


<custom_item>
  type                : FILE_CONTENT_CHECK
  description         : "20.0 Check truststore configuration in /etc/ssl/"
  file                : "/etc/ssl/openssl.cnf"
  regex               : "CApath[[:space:]]*="
  expect              : ""
  info                : "Checks the CApath configuration in /etc/ssl/openssl.cnf. IT security must manually verify that it points to '/etc/ssl/certs' or the appropriate truststore path."
  solution            : "Ensure the 'CApath' in /etc/ssl/openssl.cnf is correctly set to the truststore directory."
</custom_item>
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
    <title>Custom PrivCheck Audit File Generator</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-lg-8 col-md-10">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title mb-0">PrivCheck Audit File Generator</h3>
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

