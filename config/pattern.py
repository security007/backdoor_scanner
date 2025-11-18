SUSPICIOUS_PATTERNS = {
    # ======================
    # PYTHON
    # ======================
    r"eval\(.*\)": "Python: eval() - Potential code injection",
    r"exec\(.*\)": "Python: exec() - Arbitrary code execution",
    r"os\.system\(.*\)": "Python: os.system() - Command execution",
    r"subprocess\.(Popen|call|run)\(.*\)": "Python: subprocess execution",
    r"base64\.b64decode\(.*\)": "Python: Base64 decoding - Possible obfuscation",
    r"pickle\.loads\(.*\)": "Python: pickle.loads() - Dangerous deserialization",
    r"marshal\.loads\(.*\)": "Python: marshal.loads() - Dangerous deserialization",
    r"zlib\.decompress\(.*\)": "Python: Decompressing embedded payload",
    r"bz2\.decompress\(.*\)": "Python: BZ2 decompress - Possible packed payload",
    r"codecs\.decode\(.*\)": "Python: Decoding (hex/base64/etc)",
    r"__import__\(.*\)": "Python: Dynamic import",
    r"importlib\.import_module\(.*\)": "Python: Dynamic import via importlib",
    r"socket\.socket\(": "Python: Raw socket networking",
    r"requests\.(get|post|put|delete)\(.*\)": "Python: HTTP communication",
    r"urllib\.request\.(urlopen|Request)\(.*\)": "Python: Remote URL request",
    r"threading\.Thread\(": "Python: Thread spawn",
    r"multiprocessing\.Process\(": "Python: Process spawn",
    r"ctypes\.CDLL\(": "Python: Low-level library loading",
    r"ctypes\.windll": "Python: Windows DLL invoke",
    r"open\(.*'wb'\)": "Python: Writing binary file (payload drop)",
    r"sys\.settrace": "Python: Debug manipulation",
    r"globals\(\)\[.*\]": "Python: Dynamic variable / code injection",
    r"locals\(\)\[.*\]": "Python: Dynamic code context manipulation",

    # ======================
    # PHP
    # ======================
    r"eval\(.*\)": "PHP: eval() - Dangerous code evaluation",
    r"assert\(.*\)": "PHP: assert() used as eval",
    r"preg_replace\(\"/e\"": "PHP: preg_replace /e - Command injection",
    r"base64_decode\(.*\)": "PHP: Base64 decoding - Obfuscation",
    r"str_rot13\(.*\)": "PHP: ROT13 obfuscation",
    r"gzinflate\(.*\)": "PHP: gzinflate - Packed payload",
    r"gzuncompress\(.*\)": "PHP: gzuncompress - Packed payload",
    r"system\(.*\)": "PHP: System command",
    r"shell_exec\(.*\)": "PHP: shell_exec()",
    r"exec\(.*\)": "PHP: exec() command execution",
    r"passthru\(.*\)": "PHP: passthru() command execution",
    r"popen\(.*\)": "PHP: popen() external process",
    r"proc_open\(.*\)": "PHP: proc_open() external process",
    r"file_get_contents\(.*http": "PHP: Remote file inclusion",
    r"include\(.*http": "PHP: RFI include",
    r"require\(.*http": "PHP: RFI require",
    r"\$_GET\[.*\]": "PHP: Accessing GET variable",
    r"\$_POST\[.*\]": "PHP: Accessing POST variable",
    r"\$_REQUEST\[.*\]": "PHP: Accessing REQUEST variable",
    r"Move_uploaded_file": "PHP: File upload manipulation",
    r"php_uname": "PHP: System info disclosure",
    r"chr\([0-9]+\)\.chr": "PHP: Obfuscated string (chr chain)",
    r"error_reporting\(0\)": "PHP: Error disabling (webshell behavior)",
    r"set_time_limit\(0\)": "PHP: Long-running exec",

    # ======================
    # PERL
    # ======================
    r"eval\(.*\)": "Perl: eval() injection",
    r"system\(.*\)": "Perl: command execution",
    r"exec\(.*\)": "Perl: external command exec",
    r"open\(.*\|": "Perl: Pipe to external command",
    r"`.*`": "Perl: Backtick command execution",
    r"qx/.*?/": "Perl: qx command execution",
    r"fork\(": "Perl: Process branch (fork)",
    r"socket\(.*\)": "Perl: Raw socket usage",
    r"LWP::UserAgent->new": "Perl: HTTP communication",
    r"Crypt::CBC->new": "Perl: Decryption attempt",
    r"IO::Socket::INET->new": "Perl: Network socket creation",

    # ======================
    # ASP CLASSIC / VBScript
    # ======================
    r"Server\.CreateObject\(\"Scripting\.FileSystemObject\"\)": "ASP: File operations",
    r"Request\.Form": "ASP: POST input",
    r"Request\.QueryString": "ASP: GET input",
    r"ExecuteGlobal": "ASP: Dynamic code execution",
    r"Response\.Write": "ASP: Output manipulation",
    r"CreateObject\(\"WScript\.Shell\"\)": "ASP: Shell execution",
    r"Shell\.Application": "ASP: System command execution",
    r"Execute\(": "ASP: Executing dynamic script",

    # ======================
    # JAVASCRIPT / NODEJS
    # ======================
    r"eval\(.*\)": "JS: eval() used for dynamic code",
    r"new Function\(.*\)": "JS: Dynamic Function() eval",
    r"child_process\.(exec|execSync|spawn)": "NodeJS: Process execution",
    r"fs\.writeFileSync": "NodeJS: File writing",
    r"atob\(.*\)": "JS: Base64 decode",
    r"WebSocket\(.*\)": "JS: WebSocket communication",
    r"fetch\(.*\)": "JS: Remote HTTP request",
    r"XMLHttpRequest": "JS: Remote HTTP request",
    r"require\('vm'\)": "NodeJS: VM sandbox eval",
    r"vm\.runInContext": "NodeJS: Dynamic execution",

    # ======================
    # BASH / SHELL
    # ======================
    r"curl .*https?://": "Shell: Remote download",
    r"wget .*https?://": "Shell: Remote download",
    r"bash -c": "Shell: Inline execution",
    r"sh -c": "Shell: Inline command",
    r"base64 -d": "Shell: Payload decode",
    r"nc .* -e": "Shell: Reverse shell",
    r"mkfifo .* /dev/tcp/": "Shell: Reverse shell via FIFO",
    r"chmod \+x .*": "Shell: Making file executable",
    r"scp .*@": "Shell: Remote file transfer",
    r"sshpass": "Shell: Hardcoded credentials",

    # ======================
    # POWERSHELL
    # ======================
    r"Invoke-Expression": "PowerShell: iEx = eval",
    r"Invoke-WebRequest": "PowerShell: Remote request",
    r"New-Object Net\.WebClient": "PowerShell: File download",
    r"Start-Process": "PowerShell: External program",
    r"\[System\.Convert\]::FromBase64String": "PowerShell: Decode payload",
    r"IEX\s": "PowerShell: Abbreviated Invoke-Expression",
    r"Add-Type": "PowerShell: Load .NET assembly",
    r"Set-ItemProperty .* Run": "PowerShell: Persistence attempt",

    # ======================
    # COMMON ACROSS LANGUAGES
    # ======================
    r"base64_(en|de)code": "Common: Base64 encode/decode",
    r"base64_decode": "Common: Base64 decode",
    r"rot13": "Common: ROT13 obfuscation",
    r"md5\(.*\)": "Common: MD5 hashing",
    r"sha1\(.*\)": "Common: SHA1 hashing",
    r"fopen\(.*\)": "Common: File open",
    r"file_get_contents\(.*\)": "Common: File/URL reading",
    r"curl_setopt": "Common: Curl HTTP config",
    r"unlink\(.*\)": "Common: File deletion",
    r"strrev\(.*\)": "Common: Obfuscation via reverse string",
    r"hex2bin\(.*\)": "Common: Hex decoding",
    r"pack\('H'\)": "Common: Binary packing",
    r"error_reporting\(0\)": "Common: Hiding errors (webshell 행동)",
}
