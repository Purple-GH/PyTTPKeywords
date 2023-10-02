import json
from collections import defaultdict

# This script is essentially used to create key terms to keyword associations
# This is to supplement the automatically-generated keywords with additional values
# The keywords are formatted and output to a json file, which is then used by keyword_generator.py

##############################
#    VARIABLE DEFINITIONS    #
##############################

# This is the dict that will be dumped to the json file
keyword_dict = defaultdict(list)

# This is the list used to store the terms associated to a dict key
keyword_list = []

# These are the files used to store the additional keywords in
enterprise_file = 'additional_enterprise_keywords.json'
mobile_file = 'additional_mobile_keywords.json'

##############################
#    FUNCTION DEFINITIONS    #
##############################

# The function that appends the desired key:pair associations to the json file
def append_keywords(key, terms):
	for term in terms:
		keyword_list.append(term.lower())
	keyword_dict[key].extend(keyword_list)
	keyword_list.clear()

# This is the function for creating the enterprise keywords
def add_enterprise_keywords():

	# Keywords for TTPs involving drive-by compromise
	raw_terms = ['browser exploit', 'exploit browser', 'exploited the browser', 'exploited browsers', 'compromised website', 'cross-site scripting', 'cross site scripting', 'malicious ads', 'malicious advertisements', 'watering hole', 'shared interest', 'targeted industry', 'strategic web compromise', 'drive-by compromise', 'drive by compromise', 'adversary controlled content', 'compromised web server']
	append_keywords('drive-by', raw_terms)

	# Keywords for TTPs involving public-facing applications
	raw_terms = ['intrnet-facing', 'public-facing', 'sql injection']
	append_keywords('public-facing', raw_terms)

	# Keywords for TTPs involving legitimate remote services
	raw_terms = ['TeamViewer', 'Team Viewer', 'Go2Assist', 'LogMein', 'AmmyAdmin', 'Ammy', 'Ammy Admin', 'VNC', 'DameWare', 'ConnectWise', 'Tmate', 'ScreenConnect', 'VNCdll', 'VPN', 'virtual private network', 'Citrix', 'Windows Remote Manager', 'Windows Remote Management', 'SSH', 'remote desktop', ' RDP']
	append_keywords('external remote', raw_terms)

	# Keywords for hardware-related TTPs
	raw_terms = ['introduce computer accessories', 'add computer accessories', 'introduce networking hardware', 'add networking hardware']
	append_keywords('hardware', raw_terms)

	# Keywords for TTPs related to phishing
	raw_terms = ['social engineer', 'spearphish', 'pdf', 'doc ', 'xls', 'ppt', 'docx', 'docm']
	append_keywords('phishing', raw_terms)

	# Keywords for TTPs involving supply chain compromise
	raw_terms = ['supply chain compromise', 'compromised supply chain', 'update channel', 'compromise dependencies', 'compromise development tools', 'software supply chain', 'hardware supply chain']
	append_keywords('supply chain', raw_terms)

	# Keywords to add to encoding-related TTPs
	raw_terms = ['base 64', 'base64', 'b64', 'ascii', 'unicode', 'mime', 'encode']
	append_keywords('encode', raw_terms)

	# Keywords to add to TTPs where the malware relies on the victim to run it
	raw_terms = ['pdf', 'doc ', 'xls', 'ppt']
	append_keywords('client exec', raw_terms)

	# Keywords to add to Microsoft Office TTPs
	raw_terms = ['pdf', 'doc ', 'docx', 'docm', 'xls', 'ppt', ' word ', 'excel', 'powerpoint', 'microsoft office']
	append_keywords('office', raw_terms)

	# Keywords to add to scripting-related TTPs
	raw_terms = [' script', 'JavaScript', '.js', 'Python', '.py', 'Powershell', '.ps1', 'bash', '.sh', 'VisualBasic', '.vbs', 'VBScript', 'Ruby', '.rb', 'AutoIT', 'AutoHotKey', 'AHK', 'php']
	append_keywords('scripting', raw_terms)

	# Keywords for proxy-related TTPs
	raw_terms = ['htran', 'classfon', 'SOCKS', 'onion']
	append_keywords('proxy', raw_terms)

	# Keywords for TTPs involving shared modules
	raw_terms = ['shared modules', 'share modules', 'module loader', 'import directory', 'application manifest', 'LoadLibraryExW', 'DWriteCreateFactory', 'load DLLs into memory', 'load a DLL into memory', 'LoadLibrary']
	append_keywords('module', raw_terms)

	# Keywords for TTPs involving containers
	raw_terms = ['docker', 'kubernetes', 'kubectl', 'container', 'kubeflow', 'kubelet']
	append_keywords('container', raw_terms)

	# Keywords for TTPs that use native APIs
	raw_terms = ['native API', 'native OS API', 'low-level OS services', 'CreateProcess', 'fork', 'VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'ShellExecute', 'HttpOpenRequest', 'CreateProcessAsUser', 'CreatePipe', 'RegEnumKey', 'WinExec', 'NtQueryDirectoryFile', 'ZwQueryDirectoryFile', 'IsDebuggerPresent', 'OutputDebugString', 'SetLastError', 'GetProcAddress', 'LoadLibrary', 'Wow64SetThreadContext', 'GetUserName', 'EnumResourceTypesA', 'ConnectNamedPipe', 'WNetAddConnection2', 'ZwWriteVirtualMemory', 'ZwProtectVirtualMemory', 'ZwQueueApcThread', 'NtResumeThread', 'TerminateProcess', 'CreateRemoteThread', 'GetModuleFileName', 'lstrcat', 'CreateFile', 'ReadFile', 'GetProcessById', 'CloseHandle', 'GetCurrentHwProfile', 'FindNextUrlCacheEntryA', 'FindFirstUrlCacheEntryA', 'MoveFileEx', 'GetWindowsDirectoryW', 'process injection', 'contentsOfDirectoryAtPath', 'pathExtension']
	append_keywords(' api', raw_terms)

	# Keywords for TTPs that use scheduled tasks or jobs
	raw_terms = ['scheduled task', 'scheduled job', 'task scheduling', 'job scheduling', 'scheduler task', 'cron']
	append_keywords('scheduled task', raw_terms)

	# Keywords for TTPs involving traffic signaling
	raw_terms = ['traffic signaling', 'hides open ports', 'hide open ports', 'hide malicious', 'port knocking','unusual flags', 'specific strings', 'respond to commands', 'Wake-on-LAN', 'special string', 'magic packet', 'special packet', 'special packet']
	append_keywords('signal', raw_terms)

	# Keywords for TTPs where a trusted relationship is abused
	raw_terms = ['trusted relationship', 'third-party relationship', 'third party relationship']
	append_keywords('relationship', raw_terms)

	# Keywords for TTPs involving credential harvesting from password stores
	raw_terms = ['LaZagne', 'SmartFTP Password Decryptor', 'NetPass', 'Carberp', 'passw.plug', 'Stealer One', 'Mimikatz', 'Windows Vault', 'Credential Manager']
	append_keywords('password', raw_terms)

	# Keywords for TTPs involving the use of BITS jobs
	raw_terms = ['BITS job', 'Background Intelligent Transfer Service', 'BITSAdmin', ' BITS ', 'SetNotifyCmdLine']
	append_keywords('bits ', raw_terms)

	# This is for any Kerberos TTPs, since the main keyword generator looks for terms with more than 1 word, which removes 'Kerberos'
	raw_terms = ['Kerberos']
	append_keywords('kerberos', raw_terms)

	# Keywords for TTPs relating to Domain Trusts
	raw_terms = ['domain trust', 'DSEnumerateDomainTrusts', 'Nltest', 'Get-AcceptedDomain', 'Get-NetForestTrust']
	append_keywords('domain trust', raw_terms)

	# Keywords for TTPs relating to screen capture
	raw_terms = ['screen', 'screen capture', 'CopyFromScreen', 'screencapture', 'xwd', 'screenshot']
	append_keywords('screen', raw_terms)

	# Keywords for TTPs relating to video capture
	raw_terms = ['webcam', 'video', 'camera', 'videocam']
	append_keywords('video', raw_terms)

	# Keywords for keyboard-input related TTPs
	raw_terms = ['keystrokes', ' keylogg', 'keyboard input']
	append_keywords('input', raw_terms)

	# Keywords for audio capture TTPs
	raw_terms = ['audio', 'microphone', 'voice']
	append_keywords('audio', raw_terms)

	# Keywords related to OS credential dumping
	raw_terms = ['OS credential dumping', 'dump credentials', 'mimikatz', 'GetPassword_x64', 'HOMEFRY']
	append_keywords('dump', raw_terms)

	# Keywords for TTPs that are related to the registry
	raw_terms = ['HKEY_CURRENT_USER', 'HKCU', 'HKEY_LOCAL_MACHINE', 'HKLM', 'reg add', 'Registry', 'Registries']
	append_keywords('registry', raw_terms)

	# Keywords for TTPs relating to hidden/obfuscated information
	raw_terms = ['hide', 'obfuscate', 'conceal', 'steganography']
	append_keywords('obfuscat', raw_terms)

	# Keywords for TTPs relating to DoS
	raw_terms = ['denial of service', 'ddos', 'udp flood', 'icmp flood', 'ping flood', 'syn flood', 'ping of death', 'slowloris', 'slow loris', 'ntp amplification', 'http flood']
	append_keywords('network denial', raw_terms)

	# Keywords for TTPs relating to Application Layer protocols
	raw_terms = ['dns tunnel', 'ftp', 'tftp', 'ftps', 'file transfer protocol', 'telnet', 'ssh', 'secure shell', 'nfs', 'network file system', 'smtp', 'simple mail transfer protocol', 'smb', 'server message block', ' irc', 'internet relay chat', 'rdp', 'remote desktop', 'http', 'hypertext transfer protocol', 'pop3', 'post office protocol']
	append_keywords('application layer', raw_terms)

	# Keywords for TTPs relating to masquerading
	raw_terms = ['pretend', ' pose ', 'masquerade', 'facade', 'disguise', 'impersonate']
	append_keywords('masquerad', raw_terms)

	# Keywords for TTPs relating changing account access
	raw_terms = ['inhibit access', 'delete account', 'lock account', 'change credential', 'log users out', 'log users off']
	append_keywords('account access', raw_terms)

	# Keywords for TTPs relating to forged web credentials
	raw_terms = ['session cookie']
	append_keywords('web credential', raw_terms)

	# Keywords for TTPs relating to system information disovery
	raw_terms = ['hostname', 'os version', 'operating system version', 'service pack', 'architecture', 'computer name', 'processor', 'video card', 'cpu', 'linux version', 'windows version', 'macos version', 'osx version', 'os x version', 'host information', 'keyboard language', 'os language', 'operating system language', 'bios model', 'system volume information', 'volume serial number', 'mac address']
	append_keywords('system info', raw_terms)

	# Keywords for TTPs involving exploitation for client execution
	# Keywords for multiple categories, including Phishing and Drive-By Compromise are added since they apply
	raw_terms = ['browser exploit', 'exploit browser', 'exploited the browser', 'exploited browsers', 'compromised website', 'cross-site scripting', 'cross site scripting', 'malicious ads', 'malicious advertisements', 'watering hole', 'shared interest', 'targeted industry', 'strategic web compromise', 'drive-by compromise', 'drive by compromise', 'adversary controlled content', 'compromised web server', 'spearphish', 'phish', 'pdf', 'doc ', 'docx', 'docm', 'xls', 'ppt', ' word ', 'excel', 'powerpoint', 'microsoft office']
	append_keywords('client execution', raw_terms)

	# Keywords for TTPs involving a user executing the malware
	raw_terms = ['spearphish', 'phish', 'pdf', 'doc ', 'docx', 'docm', 'xls', 'ppt', ' word ', 'excel', 'powerpoint', 'microsoft office']
	append_keywords('user execution', raw_terms)

	# Keywords for TTPs related to Software Deployment Tools
	raw_terms = ['SCCM', 'HBSS', 'Altiris', 'McAfee ePO', 'RAdmin']
	append_keywords('software deployment', raw_terms)

	# Keywords for TTPs where the malware removes indicators of its presence
	raw_terms = ['indicator removal', 'remove indicator', 'indicator delet', 'delete indicators', 'artifact removal', 'remove artifact', 'artifact delet', 'delete artifact']
	append_keywords('indicator removal', raw_terms)

	# Keywords for TTPs related to XML Template Injection
	raw_terms = ['docx', 'xlsx', 'pptx']
	append_keywords('template injection', raw_terms)

	# Keywords for TTPs involving Man-in-the-Middle attacks
	raw_terms = ['MiTM', 'man in the middle']
	append_keywords('man-in-the-middle', raw_terms)

	# This is specifically to add ransomware to Data Encrypted for Impact, as it isn't automatically generated
	raw_terms = ['ransom', 'ransomware']
	append_keywords('encrypted for impact', raw_terms)

# This is the function for creating the mobile keywords
def add_mobile_keywords():

	# Keywords to add to TTPs where code is delivered using a legitimate app store
    raw_terms = ['google play', 'play store', 'app store']
    append_keywords('authorized', raw_terms)

    # Keywords to add to TTPs where code is delivered using alternate means
    raw_terms = ['phish', 'malicious link', 'third-party app store', 'sms link', 'email link']
    append_keywords('other means', raw_terms)

    # Keywords to add to TTPs where malware uses alternate methods for their C2 channel
    raw_terms = ['cellular network', 'SMS for command and control', 'SMS for C2', 'SMS for C&C', 'SMS C2', 'SMS C&C', 'email for command and control', 'email for C2', 'email for C&C', 'email C2', 'email C&C', 'phone calls for command and control', 'phone calls for C2', 'phone calls for C&C', 'call C2', 'call C&C', 'cellular network', 'bypass enterprise network', 'bypass monitoring system']
    append_keywords('alternate network', raw_terms)
    
    # Keywords for TTPs related to Drive-By Compromise
    raw_keywords = ['watering hole', 'drive by compromise', 'web browser exploit', 'exploit web browser']
    append_keywords('drive-by', raw_terms)
    
    # Keywords for TTPs relating to the installation of insecure or malicious configurations
    raw_terms = ['install insecure configuration', 'install malicious configuration']
    append_keywords('malicious configuration', raw_terms)
    
    # Keywords for TTPs involving Lockscreen Bypass
    raw_terms = ['lock screen bypass', 'bypass the lock screen', 'bypass the lockscreen']
    append_keywords('lockscreen', raw_terms)
    
    # Keywords for TTPs relating to masquerading
    raw_terms = ['pretend', ' pose ', 'masquerade', 'facade', 'disguise', 'impersonate']
    append_keywords('masquerad', raw_terms)
    
    # Keywords for TTPs involving the use of the command line
    raw_terms = ['Android Debug Bridge', ' ADB ', 'runtime shell']
    append_keywords('command-line', raw_terms)
    
    # Keywords for TTPs relating to the use of Native Code
    raw_terms = ['Native Development Kit', ' NDK ', 'Java Native Interface', ' JNI ']
    append_keywords('native code', raw_terms)
    
    # Keywords for TTPs that use scheduled tasks or jobs
    raw_terms = ['scheduled task', 'scheduled job', 'task scheduling', 'job scheduling', 'scheduler task', 'WorkManager', 'JobScheduler', 'GcmNetworkManager', 'AlarmManager', 'NSBackgroundActivityScheduler']
    append_keywords('scheduled', raw_terms)

########################################
#    THE CODE BEING RUN STARTS HERE    #
########################################

add_enterprise_keywords()

# Putting the final enterprise version of keyword_dict into the json file
json_file = open(enterprise_file, 'w')
json.dump(keyword_dict, json_file, indent = 4)
json_file.close()
keyword_dict.clear()

add_mobile_keywords()

# Putting the final mobile version of keyword_dict into the json file
json_file = open(mobile_file, 'w')
json.dump(keyword_dict, json_file, indent = 4)
json_file.close()
keyword_dict.clear()
