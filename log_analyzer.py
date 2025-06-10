import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import ttkbootstrap as tb
from ttkbootstrap.constants import * # Consider importing specific constants if not all are needed
import threading, time
import tkinter.font as tkfont

# Theme Configuration
PALETTE = {
    "primary":   "#1F6FEB",
    "secondary": "#48E1A5",
    "success":   "#37B24D",
    "info":      "#0EA5E9",
    "warning":   "#FBBF24",
    "danger":    "#EF4444",
    "light":     "#161B22", # Used for some backgrounds/elements
    "dark":      "#0D1117", # Main background
    "text_light": "#E6EDF3", # Main text color on dark backgrounds
    "text_dark":  "#0D1117", # Main text color on light backgrounds
    "border":    "#414B57", # Border color
}

# Constants
SPACING = 8
WINDOW_SIZE = "1280x860"
MIN_WINDOW_SIZE = (1024, 720)

# Configure matplotlib for dark theme
plt.rcParams.update({
    "text.color": PALETTE["text_light"],
    "axes.facecolor": PALETTE["light"],
    "axes.edgecolor": PALETTE["border"],
    "axes.labelcolor": PALETTE["text_light"],
    "xtick.color": PALETTE["text_light"],
    "ytick.color": PALETTE["text_light"],
    "figure.facecolor": PALETTE["light"], # Match card/element backgrounds
    "savefig.facecolor": PALETTE["light"],
    "patch.edgecolor": PALETTE["border"], # For pie chart wedge borders
})

DARK_THEME_NAME, LIGHT_THEME_NAME = "darkly", "flatly" # ttkbootstrap theme names

# Row colors based on attack type risk (used for Treeview tags and chart colors)
ROW_COLORS = {
    "Sql Injection": PALETTE["danger"],
    "Brute Force": PALETTE["warning"],
    "Dos Attack (Registration)": PALETTE["danger"],
    "Dos Attack (Invalid Credentials)": PALETTE["danger"], # Combined DoS type for coloring
    "Xss": PALETTE["danger"],
    "Command Injection": PALETTE["danger"],
    "Lfi Rfi": PALETTE["danger"],
    "Ssti": PALETTE["danger"],
    "Open Redirect": PALETTE["warning"],
    "Csrf": PALETTE["warning"],
    "Xxe": PALETTE["warning"],
    "Sensitive Data Exposure": PALETTE["danger"],
    "Jwt Attack": PALETTE["warning"],
    "Broken Auth": PALETTE["danger"],
    "Race Condition": PALETTE["danger"],
    "Privilege Escalation": PALETTE["danger"],
    "File Upload": PALETTE["danger"],
    "Business Logic": PALETTE["warning"],
    "Subdomain Takeover": PALETTE["danger"],
    "Cors Misconfig": PALETTE["warning"],
    "Idor": PALETTE["danger"],
    "Path Traversal": PALETTE["danger"],
    "Directory Listing": PALETTE["info"],
    "Http Header Injection": PALETTE["warning"],
    "Host Header Attack": PALETTE["warning"],
    "Weak Ssl": PALETTE["info"],
    "Deserialization": PALETTE["danger"],
    "Websocket Attack": PALETTE["warning"],
    "Brute Force Attack On Username": PALETTE["warning"], # Specific brute force
    "Dos": PALETTE["danger"], # Generic DoS for icons/charts if needed
}


class WebLogAnalyzer:
    def __init__(self):
        self.suspicious_ips = defaultdict(lambda: {
            'failed_logins': 0,
            'failed_registrations': 0,
            'last_attempt': None,
            'attack_patterns': set() # Stores attack_type_keys like 'sql_injection'
        })
        self.failed_usernames = defaultdict(lambda: {
            'failed_logins': 0,
            'failed_registrations': 0,
            'last_attempt': None,
            'attack_patterns': set(), # Stores attack_type_keys
            'login_attempts': deque(maxlen=3), # Stores timestamps
            'registration_attempts': deque(maxlen=3) # Stores timestamps
        })
        # Expanded attack patterns for more vulnerabilities
        # Keys are attack_type_keys, used internally and for stats['attack_types']
        self.attack_patterns = {
            'sql_injection': [
                r"'.*--", r"(?:union.*select|select.*from|drop.*table)",
                r"(?:or|and)\s+\d+\s*=\s*\d+", r"information_schema",
                r"benchmark\s*\(", r"exec\s*xp_", r"waitfor\s*delay"
            ],
            'xss': [
                r"<script.*?>", r"javascript:", r"onerror=", r"onload=",
                r"<img.*onerror=.*>", r"<svg.*onload=.*>", r"eval\s*\(", r"document\.cookie"
            ],
            'lfi_rfi': [
                r"\.\./", r"/etc/passwd", r"/proc/self/environ", r"file=",
                r"php://", r"data://", r"expect://", r"input://"
            ],
            'command_injection': [
                r";\s*ls", r"&&\s*cat", r"\|\s*whoami", r"`id`", r"\$\(id\)",
                r"exec\s*\(", r"system\s*\("
            ],
            'path_traversal': [ # Often overlaps with LFI
                r"\.\./", r"/etc/passwd", r"\.\.\\", r"\.\.%2f", r"\.\.%5c"
            ],
            'ssti': [r"\{\{.*\}\}", r"\$\{.*\}", r"\{%.*%\}"]
            ,
            'open_redirect': [
                r"redirect=.*http", r"url=.*http", r"return=.*http", r"next=.*http"
            ],
            'csrf': [r"csrf_token", r"cross-site request forgery", r"xsrf_token"],
            'xxe': [r"<!ENTITY", r"SYSTEM ", r"<!DOCTYPE", r"<!ELEMENT"],
            'directory_listing': [r"Index of /", r"Directory listing for /", r"Parent Directory"],
            'http_header_injection': [r"\r\n", r"%0d%0a", r"Set-Cookie:", r"Location:"],
            'host_header_attack': [r"Host: evil.com", r"Host: localhost", r"Host: 127.0.0.1"],
            'idor': [
                r"user_id=", r"account=", r"profile=", r"id=", r"edit/\d+", r"delete/\d+"
            ],
            'jwt_attack': [
                r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", r"Authorization: Bearer"
            ],
            'business_logic': [ # These are harder to detect with regex, more indicative
                r"logic flaw", r"race condition", r"price manipulation", r"quantity manipulation"
            ],
            'subdomain_takeover': [
                r"NoSuchBucket", r"There isn't a GitHub Pages site here.",
                r"404 Not Found", r"NXDOMAIN" # Check context for these
            ],
            'cors_misconfig': [r"Access-Control-Allow-Origin: \*", r"Access-Control-Allow-Credentials: true"],
            'sensitive_data_exposure': [ # Check responses primarily, but requests can indicate attempts
                r"password=", r"secret=", r"api_key=", r"Authorization: Bearer", # Duplicates JWT but context matters
                r"credit_card", r"ssn="
            ],
            'weak_ssl': [r"SSLv2", r"SSLv3", r"TLSv1.0", r"RC4", r"MD5"], # Usually from server config, not logs
            'broken_auth': [ # Patterns related to session/token handling
                r"sessionid=", r"auth_token=", r"rememberme=", r"Set-Cookie:", r"jwt="
            ],
            'privilege_escalation': [r"admin=1", r"role=admin", r"isAdmin=true", r"userType=admin"],
            'race_condition': [r"race condition", r"TOCTOU", r"time of check to time of use"], # Hard via logs
            'file_upload': [
                r'Content-Disposition: form-data; name="file"', r"multipart/form-data",
                r"\.php$", r"\.jsp$", r"\.asp$" # Dangerous file extensions
            ],
            'deserialization': [
                r'O:8:"stdClass":', r"__wakeup", r"__destruct", r"ObjectInputStream", r"readObject"
            ],
            'websocket_attack': [r"Sec-WebSocket-Key", r"websocket", r"ws://", r"wss://"]
        }
        # This pattern is for a very specific log format indicating repeated failures.
        self.repeated_failed_pattern_details = {
            'pattern_lines': [ # Exact lines expected for this specific pattern
                "Name:",
                "Date Login:",
                "IP Address:",
                "Login Status: Failed",
                "Process Type: Not matched data"
            ],
            'count_per_ip': defaultdict(int) # Tracks count of this specific pattern for each IP
        }

    def parse_logs(self):
        weblogs_path = Path('data/Weblogs.csv')
        reports_path = Path('data/reports.txt') # Secondary source of suspicious IPs

        # Reset stats for each parse run
        self.suspicious_ips.clear()
        self.failed_usernames.clear()
        self.repeated_failed_pattern_details['count_per_ip'].clear()

        stats = {
            'total_requests': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'failed_registrations': 0,
            'successful_registrations': 0,
            # 'failed_usernames_count': 0, # This was ambiguous, using len(self.failed_usernames) later
            'potential_attacks': [], # List of dicts, each an attack instance
            'suspicious_ips_set': set(), # Set of IPs from reports.txt or flagged
            'attack_types': defaultdict(int) # Counts occurrences of each attack_type_key
        }

        if weblogs_path.exists():
            try:
                with open(weblogs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    current_entry_lines = []
                    for line in f:
                        stripped_line = line.strip()
                        if stripped_line.startswith('+-+-+-'): # Delimiter for log entries
                            if current_entry_lines:
                                self._analyze_entry(current_entry_lines, stats)
                            current_entry_lines = []
                        elif stripped_line:
                            current_entry_lines.append(stripped_line)
                    if current_entry_lines: # Process the last entry
                        self._analyze_entry(current_entry_lines, stats)
            except Exception as e:
                print(f"Error reading or parsing Weblogs.csv: {e}")


        if reports_path.exists():
            try:
                with open(reports_path, 'r', encoding='utf-8', errors='ignore') as f:
                    current_report_entry_lines = []
                    for line in f:
                        stripped_line = line.strip()
                        if stripped_line.startswith('--'): # Delimiter for report entries
                            if current_report_entry_lines:
                                self._analyze_report_entry(current_report_entry_lines, stats)
                            current_report_entry_lines = []
                        elif stripped_line:
                            current_report_entry_lines.append(stripped_line)
                    if current_report_entry_lines: # Process the last entry
                        self._analyze_report_entry(current_report_entry_lines, stats)
            except Exception as e:
                print(f"Error reading or parsing reports.txt: {e}")
        
        # Consolidate suspicious IPs from various sources into stats['suspicious_ips_set']
        for ip in self.suspicious_ips:
            stats['suspicious_ips_set'].add(ip)

        return stats

    def _analyze_entry(self, entry_lines, stats):
        entry_data = {}
        for line in entry_lines:
            if ': ' in line:
                key, value = line.split(': ', 1)
                entry_data[key.strip()] = value.strip()

        if not entry_data: # Skip if entry is empty or malformed
            return

        stats['total_requests'] += 1 # Assuming each entry is a request

        ip = entry_data.get('IP Address', 'Unknown')
        username = entry_data.get('Name', 'Unknown')
        # Determine timestamp, preferring login then register
        timestamp_str = entry_data.get('Date Login') or entry_data.get('Date Register') or ''
        
        process_type = entry_data.get('Process Type', '')
        login_status = entry_data.get('Login Status', '')
        register_status = entry_data.get('Register Status', '')

        parsed_timestamp = None
        if timestamp_str:
            try:
                parsed_timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                # print(f"Warning: Could not parse timestamp '{timestamp_str}' for IP {ip}")
                pass # Keep parsed_timestamp as None

        # Handle registration status
        if register_status == 'Successful':
            stats['successful_registrations'] += 1
        elif register_status == 'Failed':
            stats['failed_registrations'] += 1
            if ip != 'Unknown':
                self.suspicious_ips[ip]['failed_registrations'] += 1
            if username != 'Unknown' and parsed_timestamp:
                 self.failed_usernames[username]['registration_attempts'].append(parsed_timestamp)
                 # Check for DoS on registration
                 if len(self.failed_usernames[username]['registration_attempts']) == 3:
                    times = list(self.failed_usernames[username]['registration_attempts'])
                    if (times[2] - times[0]).total_seconds() <= 10: # 3 attempts in 10s
                        if 'dos_registration' not in self.failed_usernames[username]['attack_patterns']:
                            stats['potential_attacks'].append({
                                'type': 'Dos Attack (Registration)',
                                'username': username,
                                'ip': ip,
                                'timestamp': timestamp_str,
                                'details': 'Three failed registration attempts in 10 seconds.'
                            })
                            stats['attack_types']['dos_registration'] +=1
                            self.failed_usernames[username]['attack_patterns'].add('dos_registration')
                            self.suspicious_ips[ip]['attack_patterns'].add('dos_registration')


        # Handle login status
        if login_status == 'Successful':
            stats['successful_logins'] += 1
        elif login_status == 'Failed':
            stats['failed_logins'] += 1
            if ip != 'Unknown':
                self._check_brute_force_ip(ip, timestamp_str, stats) # Check for IP-based brute force
            if username != 'Unknown':
                self._check_brute_force_username(username, ip, timestamp_str, stats) # Check for username-based brute force
            
            # DoS on login with "Not matched data"
            if process_type == 'Not matched data' and username != 'Unknown' and parsed_timestamp:
                user_data_dos = self.failed_usernames[username] # Use a different var name to avoid confusion
                user_data_dos['login_attempts'].append(parsed_timestamp)
                if len(user_data_dos['login_attempts']) == 3:
                    times = list(user_data_dos['login_attempts'])
                    if (times[2] - times[0]).total_seconds() <= 10:
                        if 'dos_login_invalid_creds' not in user_data_dos['attack_patterns']:
                            stats['potential_attacks'].append({
                                'type': 'Dos Attack (Invalid Credentials)',
                                'username': username,
                                'ip': ip,
                                'timestamp': timestamp_str,
                                'details': 'Three "Not matched data" login attempts in 10 seconds.'
                            })
                            stats['attack_types']['dos_login_invalid_creds'] += 1
                            user_data_dos['attack_patterns'].add('dos_login_invalid_creds')
                            self.suspicious_ips[ip]['attack_patterns'].add('dos_login_invalid_creds')
        
        # Check for the specific repeated failed login pattern (e.g., from a custom log source)
        # This is a very specific check based on exact line matching.
        expected_pattern_lines = [
            f"Name: {entry_data.get('Name', '')}",
            f"Date Login: {entry_data.get('Date Login', '')}",
            f"IP Address: {entry_data.get('IP Address', '')}",
            "Login Status: Failed",
            "Process Type: Not matched data"
        ]
        # Normalize entry_lines for comparison (key: value format)
        formatted_entry_for_pattern_check = [f"{k}: {v}" for k,v in entry_data.items()]

        is_specific_pattern_match = True
        # This check is tricky. Let's assume the original intent was simpler:
        # If the entry_data contains the specific fields with specific values.
        if (entry_data.get("Login Status") == "Failed" and
            entry_data.get("Process Type") == "Not matched data" and
            "Name" in entry_data and "Date Login" in entry_data and "IP Address" in entry_data):
            
            self.repeated_failed_pattern_details['count_per_ip'][ip] += 1
            if self.repeated_failed_pattern_details['count_per_ip'][ip] >= 3: # Threshold for this specific pattern
                # Avoid duplicate "Brute Force Attack" entries if already caught by general brute force logic
                is_already_brute_forced = any(
                    att['type'] == 'Brute Force' and att['ip'] == ip
                    for att in stats['potential_attacks']
                )
                if not is_already_brute_forced and 'brute_force_specific_pattern' not in self.suspicious_ips[ip]['attack_patterns']:
                    stats['potential_attacks'].append({
                        'type': 'Brute Force', # Generalize to Brute Force
                        'ip': ip,
                        'username': username,
                        'timestamp': timestamp_str,
                        'details': 'Repeated specific failed login pattern detected 3+ times (potential brute force).'
                    })
                    stats['attack_types']['brute_force'] += 1 # Use 'brute_force' key
                    self.suspicious_ips[ip]['attack_patterns'].add('brute_force_specific_pattern')


        # Check for generic attack patterns in the combined values of the entry
        # Search across all values in the current log entry
        search_payload_string = " ".join(str(v) for v in entry_data.values())
        self._check_generic_attack_patterns(search_payload_string, ip, username, stats, timestamp_str, entry_data)


    def _analyze_report_entry(self, entry_lines, stats):
        """Analyzes entries from a secondary reports.txt file."""
        entry_data = {}
        for line in entry_lines:
            if ': ' in line:
                key, value = line.split(': ', 1)
                entry_data[key.strip()] = value.strip()
        
        ip = entry_data.get('IP Address')
        if ip:
            stats['suspicious_ips_set'].add(ip)
            # You might want to increment a specific counter or add to suspicious_ips defaultdict here
            # For now, just adding to the set.
            self.suspicious_ips[ip]['failed_logins'] += 1 # Assuming report entries imply failed activity


    def _check_brute_force_username(self, username, ip, timestamp_str, stats):
        """Checks for brute force attempts targeted at a specific username."""
        if not timestamp_str: return
        try:
            current_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return

        user_data = self.failed_usernames[username]
        user_data['failed_logins'] += 1
        user_data['last_attempt'] = current_time
        
        # Threshold for username-based brute force
        if user_data['failed_logins'] >= 5: # e.g., 5 failed attempts for a single username
            # Check if this specific (username, brute_force_user) attack was already logged
            attack_key_for_user = 'brute_force_user' # Internal key
            if attack_key_for_user not in user_data['attack_patterns']:
                stats['potential_attacks'].append({
                    'type': 'Brute Force Attack On Username', # Report type
                    'username': username,
                    'ip': ip, # Include IP that made the attempt
                    'timestamp': timestamp_str,
                    'details': f"{user_data['failed_logins']} failed login attempts for username '{username}'."
                })
                stats['attack_types']['brute_force'] += 1 # General brute_force category
                user_data['attack_patterns'].add(attack_key_for_user)
                self.suspicious_ips[ip]['attack_patterns'].add('brute_force')


    def _check_brute_force_ip(self, ip, timestamp_str, stats):
        """Checks for brute force attempts from a specific IP address."""
        if not timestamp_str: return
        try:
            current_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return

        ip_data = self.suspicious_ips[ip]
        ip_data['failed_logins'] += 1 # Increment failed logins for this IP

        # Check for rapid succession of failures from this IP
        if ip_data['last_attempt']:
            time_diff = current_time - ip_data['last_attempt']
            # e.g., 10 failed logins from an IP within 5 minutes
            if time_diff < timedelta(minutes=5) and ip_data['failed_logins'] >= 10:
                attack_key_for_ip = 'brute_force_ip' # Internal key
                if attack_key_for_ip not in ip_data['attack_patterns']:
                    stats['potential_attacks'].append({
                        'type': 'Brute Force', # Report type
                        'ip': ip,
                        'timestamp': timestamp_str,
                        'details': f"{ip_data['failed_logins']} failed login attempts from IP {ip} in a short period."
                    })
                    stats['attack_types']['brute_force'] += 1 # General brute_force category
                    ip_data['attack_patterns'].add(attack_key_for_ip)
        
        ip_data['last_attempt'] = current_time


    def _check_generic_attack_patterns(self, payload_string, ip, username, stats, entry_timestamp_str, entry_data_dict):
        """Checks the payload_string against a list of known generic attack patterns."""
        # Tracks attack_type_keys (e.g., 'sql_injection') found in this specific payload_string
        # to ensure stats['attack_types'] is incremented only once per type for this entry.
        identified_in_this_entry = set() 

        for attack_type_key, patterns_list in self.attack_patterns.items():
            for pattern_regex in patterns_list:
                # Using re.IGNORECASE for broader matching
                if re.search(pattern_regex, payload_string, re.IGNORECASE):
                    # An attack of this type_key (e.g., 'sql_injection') is found
                    if attack_type_key not in identified_in_this_entry:
                        stats['attack_types'][attack_type_key] += 1
                        identified_in_this_entry.add(attack_type_key)

                    # Add detailed record to potential_attacks for this specific pattern match
                    attack_details = {
                        'type': attack_type_key.replace('_', ' ').title(), # User-friendly type
                        'ip': ip,
                        'username': username if username != 'Unknown' else None,
                        'timestamp': entry_timestamp_str if entry_timestamp_str else datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'details': f"Matched pattern: {pattern_regex}",
                        # Optionally include a snippet of the payload or relevant log fields
                        # 'payload_snippet': payload_string[:100] + "..." if len(payload_string) > 100 else payload_string,
                        # 'relevant_log_field': entry_data_dict.get('Querystring', '') # Example
                    }
                    stats['potential_attacks'].append(attack_details)
                    
                    # Mark that this IP has exhibited this type of attack pattern
                    if ip != 'Unknown':
                        self.suspicious_ips[ip]['attack_patterns'].add(attack_type_key)
                    
                    # If a username is associated, mark it too
                    if username != 'Unknown':
                         self.failed_usernames[username]['attack_patterns'].add(attack_type_key)
                    
                    # Do not break from inner loop (patterns_list): 
                    # Allow all matching patterns for this attack_type_key to be logged in potential_attacks.
                    # The identified_in_this_entry set handles the +1 for stats['attack_types'].
        # Do not break from outer loop (self.attack_patterns.items()): check for all types of attacks.

    def _get_attack_icon(self, attack_type_str: str) -> str:
        """Gets an icon for a given attack type string."""
        icons = {
            "Sql Injection": "🧬", "Brute Force": "🔁", "Dos": "💥", "Xss": "⚠️",
            "Command Injection": "📟", "Lfi Rfi": "📂", "Ssti": "🧪",
            "Open Redirect": "🔀", "Csrf": "🔓", "Xxe": "📦",
            "Sensitive Data Exposure": "🔐", "Jwt Attack": "🔑", "Broken Auth": "🧱",
            "Race Condition": "⏱️", "Privilege Escalation": "🛡️", "File Upload": "📤",
            "Business Logic": "📊", "Subdomain Takeover": "🌐", "Cors Misconfig": "�",
            "Idor": "🆔", "Path Traversal": "🧭",
            "Brute Force Attack On Username": "👤",
            "Dos Attack (Registration)": "💥",
            "Dos Attack (Invalid Credentials)": "💥",
            "Directory Listing": "🗂️", "Http Header Injection": "💉",
            "Host Header Attack": "🎯", "Weak Ssl": "📉",
            "Deserialization": "🧩", "Websocket Attack": "🔗",
        }
        # Normalize the input attack_type_str to match keys (Title Case, spaces)
        normalized_attack_type = attack_type_str.replace('_', ' ').title()
        return icons.get(normalized_attack_type, "⚔️") # Default icon

    def generate_report(self):
        """Generates a summary text report of the analysis."""
        stats = self.parse_logs() # Re-parse logs to get fresh stats for the report
        report_lines = []
        report_lines.append("🔐 Web Security Analysis Report")
        report_lines.append(f"📅 Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("═" * 60)

        report_lines.append("\n📊 Summary Statistics:")
        report_lines.append(f"  • Total Requests Analyzed....: {stats['total_requests']}")
        report_lines.append(f"  • ✅ Successful Logins........: {stats['successful_logins']}")
        report_lines.append(f"  • ❌ Failed Logins............: {stats['failed_logins']}")
        report_lines.append(f"  • ✅ Successful Registrations..: {stats['successful_registrations']}")
        report_lines.append(f"  • ❌ Failed Registrations.....: {stats['failed_registrations']}")
        report_lines.append(f"  • 🚨 Suspicious IPs Identified: {len(stats['suspicious_ips_set'])}") # Use the set from stats

        if stats['attack_types']:
            report_lines.append("\n🛡️ Detected Attack Types (Total Occurrences):")
            # Sort attack types alphabetically for consistent reporting
            for attack_type_key in sorted(stats['attack_types'].keys()):
                count = stats['attack_types'][attack_type_key]
                user_friendly_name = attack_type_key.replace('_', ' ').title()
                icon = self._get_attack_icon(user_friendly_name)
                report_lines.append(f"  • {icon} {user_friendly_name:<30}: {count}")
        else:
            report_lines.append("\n🛡️ No specific attack types detected in this analysis run.")

        if stats['potential_attacks']:
            report_lines.append("\n📌 Detailed Potential Attack Incidents (Sorted by Time):")
            report_lines.append("─" * 60)
            # Sort potential attacks by timestamp (if available)
            # Handle cases where timestamp might be None or not a string
            def get_sort_key(attack_item):
                ts = attack_item.get('timestamp')
                if isinstance(ts, str) and ts:
                    try:
                        return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        return datetime.min # Fallback for unparseable strings
                return datetime.min # Fallback for None or empty timestamps
            
            sorted_attacks = sorted(stats['potential_attacks'], key=get_sort_key)

            for i, attack in enumerate(sorted_attacks, 1):
                attack_type_title = attack['type'] # Already title-cased
                report_lines.append(f"\n{i}️⃣ Attack Type: {self._get_attack_icon(attack_type_title)} {attack_type_title}")
                if attack.get('ip'):
                    report_lines.append(f"  🔗 Source IP.......: {attack['ip']}")
                if attack.get('username'):
                    report_lines.append(f"  👤 Username........: {attack['username']}")
                if attack.get('timestamp'):
                    report_lines.append(f"  🕒 Timestamp.......: {attack['timestamp']}")
                if attack.get('details'):
                    report_lines.append(f"  📝 Details.........: {attack['details']}")
                if attack.get('input_payload'): # If you add this field
                    report_lines.append(f"  🧪 Input Snippet...: `{attack['input_payload']}`")
                elif attack.get('log_entry_summary'): # If you add this field
                     report_lines.append(f"  📋 Log Summary.....: {attack['log_entry_summary']}")
                report_lines.append("─" * 60)
        else:
            report_lines.append("\n📌 No specific potential attack incidents logged in detail.")
        
        # Save the report to a file
        report_path = Path('data/security_analysis_report.txt')
        report_path.parent.mkdir(parents=True, exist_ok=True) # Ensure 'data' directory exists
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report_lines))
        except Exception as e:
            print(f"Error writing security_analysis_report.txt: {e}")
            
        return '\n'.join(report_lines)

    def _generate_visualization_files(self, stats):
        """Generates and saves visualization image files. Called if GUI needs to save them."""
        vis_dir = Path('data/visualizations')
        vis_dir.mkdir(parents=True, exist_ok=True) # Ensure 'data/visualizations' directory exists
        
        attack_dist_path = vis_dir / 'attack_distribution.png'
        login_attempts_path = vis_dir / 'login_attempts.png'
        registration_attempts_path = vis_dir / 'registration_attempts.png' # New chart

        # Attack Type Distribution Pie Chart
        plt.figure(figsize=(10, 8))
        if stats['attack_types']:
            labels = [k.replace('_', ' ').title() for k in stats['attack_types'].keys()]
            sizes = list(stats['attack_types'].values())
            chart_colors = [ROW_COLORS.get(label, PALETTE["info"]) for label in labels]
            explode = [0.05] * len(sizes)

            plt.pie(
                sizes, labels=labels, autopct='%1.1f%%', startangle=140,
                colors=chart_colors, explode=explode, shadow=True,
                wedgeprops={'edgecolor': PALETTE["border"]},
                textprops={'color': PALETTE["text_light"]}
            )
            plt.title('Attack Type Distribution', color=PALETTE["text_light"])
        else:
            plt.text(0.5, 0.5, 'No Attacks Detected', fontsize=16, ha='center', va='center', color=PALETTE["text_light"])
            plt.title('Attack Type Distribution', color=PALETTE["text_light"])
            plt.axis('off')
        plt.savefig(attack_dist_path)
        plt.close()

        # Login Attempts Bar Chart
        plt.figure(figsize=(10, 6))
        if stats['successful_logins'] > 0 or stats['failed_logins'] > 0 :
            plt.bar(['Successful', 'Failed'], 
                    [stats['successful_logins'], stats['failed_logins']],
                    color=[PALETTE["success"], PALETTE["danger"]])
            plt.title('Login Attempts Overview', color=PALETTE["text_light"])
            plt.ylabel('Attempt Count', color=PALETTE["text_light"])
        else:
            plt.text(0.5, 0.5, 'No Login Data', fontsize=16, ha='center', va='center', color=PALETTE["text_light"])
            plt.title('Login Attempts Overview', color=PALETTE["text_light"])
            plt.axis('off')
        plt.savefig(login_attempts_path)
        plt.close()

        # Registration Attempts Bar Chart
        plt.figure(figsize=(10, 6))
        if stats['successful_registrations'] > 0 or stats['failed_registrations'] > 0:
            plt.bar(['Successful', 'Failed'],
                    [stats['successful_registrations'], stats['failed_registrations']],
                    color=[PALETTE["success"], PALETTE["danger"]])
            plt.title('Registration Attempts Overview', color=PALETTE["text_light"])
            plt.ylabel('Attempt Count', color=PALETTE["text_light"])
        else:
            plt.text(0.5, 0.5, 'No Registration Data', fontsize=16, ha='center', va='center', color=PALETTE["text_light"])
            plt.title('Registration Attempts Overview', color=PALETTE["text_light"])
            plt.axis('off')
        plt.savefig(registration_attempts_path)
        plt.close()
        print("Visualization files saved to data/visualizations/")


    def generate_attacker_reports(self, stats_data=None):
        """
        Generate detailed reports for each attacker (IP + username combination)
        with comprehensive analysis of their activities and attack patterns.
        Saves reports to 'data/attacker_reports/'.
        """
        if stats_data is None:
            stats_data = self.parse_logs() # Use fresh stats if not provided

        all_attacker_reports_str = []
        grouped_attacks_by_attacker = {} # Key: (ip, username_or_None)

        for attack in stats_data['potential_attacks']:
            ip = attack.get('ip', 'Unknown_IP')
            # Use username if present, otherwise consider it an IP-only attack context
            username = attack.get('username') # Can be None
            attacker_key = (ip, username)

            if attacker_key not in grouped_attacks_by_attacker:
                grouped_attacks_by_attacker[attacker_key] = {
                    'attacks_instances': [], 'unique_attack_types': set(),
                    'timestamps': [], 'payload_indicators': [], 'details_list': []
                }
            
            grouped_attacks_by_attacker[attacker_key]['attacks_instances'].append(attack)
            grouped_attacks_by_attacker[attacker_key]['unique_attack_types'].add(attack['type'])
            if attack.get('timestamp'):
                grouped_attacks_by_attacker[attacker_key]['timestamps'].append(attack['timestamp'])
            # Add more relevant fields if needed, e.g., from attack['details'] or a payload snippet

        if not grouped_attacks_by_attacker:
            return "No attackers with specific patterns detected to generate individual reports."

        for (ip, username), data in grouped_attacks_by_attacker.items():
            attacker_report = []
            attacker_report.append("══════════════════════════════════════")
            attacker_report.append(f"🧑‍💻 Attacker Summary Report")
            attacker_report.append("══════════════════════════════════════")
            attacker_report.append("")
            attacker_report.append(f"🔗 IP Address: {ip}")
            if username:
                attacker_report.append(f"👤 User Context: {username}")
            
            timestamps = sorted([ts for ts in data['timestamps'] if ts]) # Filter out None/empty and sort
            first_seen = min(timestamps) if timestamps else "N/A"
            last_seen = max(timestamps) if timestamps else "N/A"
            
            attacker_report.append(f"🕒 First Activity: {first_seen}")
            attacker_report.append(f"🕒 Last Activity : {last_seen}")
            attacker_report.append(f"💥 Total Incidents: {len(data['attacks_instances'])}")
            attacker_report.append("")

            attacker_report.append("🚨 Detected Attack Types:")
            for atype_title in sorted(list(data['unique_attack_types'])):
                icon = self._get_attack_icon(atype_title)
                attacker_report.append(f"  • {icon} {atype_title}")
            attacker_report.append("")

            attacker_report.append("📝 Detailed Actions (Chronological):")
            attacker_report.append("──────────────────────────────────────")
            
            # Sort attack instances by timestamp for this attacker
            def get_sort_key_instance(attack_item):
                ts = attack_item.get('timestamp')
                if isinstance(ts, str) and ts:
                    try: return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                    except ValueError: return datetime.min 
                return datetime.min
            
            sorted_instances = sorted(data['attacks_instances'], key=get_sort_key_instance)

            for i, attack_instance in enumerate(sorted_instances, 1):
                ts = attack_instance.get('timestamp', 'N/A')
                attacker_report.append(f"{i}. [{ts}] - {self._get_attack_icon(attack_instance['type'])} {attack_instance['type']}")
                if attack_instance.get('username'): # If this specific instance had a username
                     attacker_report.append(f"  • Target User: {attack_instance['username']}")
                if attack_instance.get('details'):
                     attacker_report.append(f"  • Details: {attack_instance['details']}")
                # Add more fields like payload snippet if available in attack_instance
                if i < len(sorted_instances): attacker_report.append("") # Spacer

            attacker_report.append("──────────────────────────────────────")
            attacker_report.append("")

            risk_level_str = self._calculate_risk_score(data['unique_attack_types'], len(data['attacks_instances']))
            attacker_report.append(f"🧩 Risk Assessment: {risk_level_str}")
            attacker_report.append("📈 Recommendations:")
            if risk_level_str == "🔥 HIGH":
                attacker_report.append(f"  • Immediately block IP: {ip} at the firewall.")
                attacker_report.append("  • Investigate logs for successful breaches or lateral movement from this IP.")
                if username: attacker_report.append(f"  • Force password reset & review activity for user: {username}.")
            elif risk_level_str == "⚠️ MEDIUM":
                attacker_report.append(f"  • Monitor IP: {ip} closely for further suspicious activity.")
                attacker_report.append("  • Consider rate-limiting or temporary IP block if activity persists.")
                if username: attacker_report.append(f"  • Alert user: {username} to review account activity if applicable.")
            else: # LOW
                attacker_report.append("  • Continue routine monitoring.")
                attacker_report.append("  • Ensure security patches and WAF rules are up-to-date.")
            
            attacker_report.append("══════════════════════════════════════\n")
            all_attacker_reports_str.extend(attacker_report)

        # Save combined attacker reports to a single file
        reports_dir = Path('data/attacker_reports')
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp_file = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file_path = reports_dir / f'attackers_summary_{timestamp_file}.txt'
        try:
            with open(report_file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_attacker_reports_str))
            print(f"Attacker reports saved to: {report_file_path}")
        except Exception as e:
            print(f"Error writing attacker reports file: {e}")
            
        return "\n".join(all_attacker_reports_str)


    def _calculate_risk_score(self, unique_attack_types_titles, attempt_count):
        """Calculate a risk score based on attack types (titles) and number of attempts"""
        # Ensure attack type titles here match those in ROW_COLORS or _get_attack_icon keys
        high_risk_titles = {
            'Sql Injection', 'Command Injection', 'Xss', 'Path Traversal', 'Lfi Rfi', 
            'Dos Attack (Registration)', 'Dos Attack (Invalid Credentials)', 'Broken Auth', 
            'Race Condition', 'Privilege Escalation', 'File Upload', 'Sensitive Data Exposure', 
            'Idor', 'Subdomain Takeover', 'Deserialization'
        }
        medium_risk_titles = {
            'Brute Force', 'Brute Force Attack On Username', 'Open Redirect', 'Jwt Attack', 
            'Business Logic', 'Cors Misconfig', 'Xxe', 'Http Header Injection', 
            'Host Header Attack', 'Websocket Attack'
        }

        has_high_risk = any(att_title in high_risk_titles for att_title in unique_attack_types_titles)
        has_medium_risk = any(att_title in medium_risk_titles for att_title in unique_attack_types_titles)

        if has_high_risk or attempt_count >= 10: # High risk if any high-severity attack or many attempts
            return "🔥 HIGH"
        elif has_medium_risk or attempt_count >= 5:
            return "⚠️ MEDIUM"
        else:
            return "ℹ️ LOW"


class LogAnalyzerGUI:
    def __init__(self, app_window):
        self.app = app_window
        self.analyzer = WebLogAnalyzer()
        self.current_page_name = None
        self.data_loaded_successfully = False
        self.current_stats_data = None # Stores the result of the last analysis
        self.search_var = tk.StringVar()

        # Define fonts first, so they can be used in style configurations
        self.font_default = tkfont.Font(family="Segoe UI", size=10)
        self.font_bold = tkfont.Font(family="Segoe UI", size=10, weight="bold")
        self.font_title = tkfont.Font(family="Segoe UI", size=18, weight="bold")
        self.font_subtitle = tkfont.Font(family="Segoe UI", size=12)
        self.font_sidebar_nav = tkfont.Font(family="Segoe UI", size=11)
        self.font_sidebar_label = tkfont.Font(family="Segoe UI", size=9, weight="bold")
        self.font_sidebar_footer = tkfont.Font(family="Segoe UI", size=8)
        self.font_stat_card_icon = tkfont.Font(family="Segoe UI", size=16)
        self.font_stat_card_title = tkfont.Font(family="Segoe UI", size=10)
        self.font_stat_card_value = tkfont.Font(family="Segoe UI", size=22, weight="bold")
        self.font_welcome_icon = tkfont.Font(family="Segoe UI", size=72, weight="bold")
        self.font_welcome_title = tkfont.Font(family="Segoe UI", size=28, weight="bold")
        self.font_welcome_subtitle = tkfont.Font(family="Segoe UI", size=16)
        self.font_welcome_version = tkfont.Font(family="Segoe UI", size=10)
        self.font_loading_title = tkfont.Font(family="Segoe UI", size=14, weight="bold")
        self.font_loading_status = tkfont.Font(family="Segoe UI", size=10)
        self.font_scrolled_text = tkfont.Font(family="Consolas", size=11)
        self.font_raw_logs = tkfont.Font(family="Consolas", size=10)
        self.font_treeview_heading = tkfont.Font(family="Segoe UI", size=10, weight="bold")


        self._setup_theme_and_styles()
        self._setup_main_layout()
        # self._setup_custom_fonts() # Custom font loading can be unreliable, stick to tkfont.Font objects
        self._bind_global_events()

        self.show_page("welcome") # Start with the welcome page

    def animate_value(self, label_widget, start_val, end_val, increment_step=1, delay_ms=15):
        """Animates a numerical value in a label."""
        current_val = start_val
        def _update_animation():
            nonlocal current_val
            if start_val < end_val: # Increasing
                current_val = min(current_val + increment_step, end_val)
            elif start_val > end_val: # Decreasing
                current_val = max(current_val - increment_step, end_val)
            
            label_widget.config(text=str(current_val))

            if current_val != end_val:
                self.app.after(delay_ms, _update_animation)
        
        _update_animation()


    def sort_treeview_column(self, treeview_widget, column_name, is_reverse_sort=False):
        """Sorts a Treeview column. Handles numeric, date, and string data."""
        items = treeview_widget.get_children("")
        
        # Create a list of (value, item_id) tuples
        data_to_sort = []
        for item_id in items:
            raw_value = treeview_widget.set(item_id, column_name)
            # Attempt to convert to a more specific type for sorting
            try:
                if column_name in ("Time", "Timestamp") and raw_value and raw_value != 'N/A':
                    # Ensure consistent datetime format for sorting
                    sort_value = datetime.strptime(raw_value, '%Y-%m-%d %H:%M:%S')
                elif column_name in ("Total Attempts", "Count", "Failed Logins", "Successful Logins", 
                                     "Failed Registrations", "Successful Registrations", "Suspicious IPs"):
                    sort_value = int(raw_value) if raw_value.isdigit() else -1 # Handle non-numeric gracefully
                else:
                    sort_value = raw_value.lower() # Case-insensitive string sort
            except ValueError:
                sort_value = raw_value.lower() # Fallback for parsing errors
            data_to_sort.append((sort_value, item_id))

        data_to_sort.sort(reverse=is_reverse_sort)

        for index, (_, item_id) in enumerate(data_to_sort):
            treeview_widget.move(item_id, "", index)

        # Update the heading command to toggle sort direction
        treeview_widget.heading(column_name, command=lambda: self.sort_treeview_column(treeview_widget, column_name, not is_reverse_sort))

    def filter_treeview_rows(self, *args):
        """Filters rows in the attacks_tree based on the search_var content."""
        query = self.search_var.get().lower().strip()
        
        if not hasattr(self, 'attacks_tree'): return # Ensure tree exists

        for item_id in self.attacks_tree.get_children(""):
            item_values = self.attacks_tree.item(item_id, "values")
            row_text_content = " ".join(str(val).lower() for val in item_values)
            
            current_tags = list(self.attacks_tree.item(item_id, "tags"))
            is_currently_hidden = "hidden_by_filter" in current_tags
            
            # Row should be hidden if query is not empty AND query is not in row content
            should_be_hidden_now = bool(query and query not in row_text_content)

            if should_be_hidden_now and not is_currently_hidden:
                current_tags.append("hidden_by_filter")
                self.attacks_tree.item(item_id, tags=tuple(current_tags))
            elif not should_be_hidden_now and is_currently_hidden:
                current_tags.remove("hidden_by_filter")
                self.attacks_tree.item(item_id, tags=tuple(current_tags))
        
        # Ensure the "hidden_by_filter" tag is configured to hide rows
        # This should be configured once after tree creation.
        # self.attacks_tree.tag_configure("hidden_by_filter", foreground=PALETTE["dark"], background=PALETTE["dark"])
        # A more effective way to "hide" rows in Treeview is to detach them,
        # but for simplicity, the color trick is used. If performance is an issue for many rows,
        # detaching/reattaching or rebuilding the tree with filtered items is better.


    def _setup_theme_and_styles(self):
        style = self.app.style # ttkbootstrap style object

        # Base style for all widgets
        style.configure(".", background=PALETTE["dark"], foreground=PALETTE["text_light"], font=self.font_default)

        # Button styles
        style.configure("TButton", padding=(10, 5), font=self.font_bold)
        style.map("TButton", background=[("active", PALETTE["info"])], foreground=[("active", PALETTE["text_light"])])
        
        style.configure("primary.TButton", background=PALETTE["primary"], foreground=PALETTE["text_light"])
        style.map("primary.TButton", background=[("active", PALETTE["info"])])
        
        style.configure("secondary.TButton", background=PALETTE["secondary"], foreground=PALETTE["text_dark"]) # Dark text on light green
        style.map("secondary.TButton", background=[("active", "#6EEAB9")]) # Slightly lighter green on active

        style.configure("primary-outline.TButton", foreground=PALETTE["primary"])
        style.map("primary-outline.TButton", foreground=[("active", PALETTE["info"])])


        # Frame styles
        style.configure("TFrame", background=PALETTE["dark"])
        style.configure("light.TFrame", background=PALETTE["light"]) # For cards or lighter sections
        style.configure("card.TFrame", background=PALETTE["light"], relief="flat", borderwidth=0)

        # LabelFrame styles
        style.configure("TLabelframe", background=PALETTE["dark"], foreground=PALETTE["text_light"], relief="solid", borderwidth=1, bordercolor=PALETTE["border"])
        style.configure("TLabelframe.Label", background=PALETTE["dark"], foreground=PALETTE["text_light"], font=tkfont.Font(family="Segoe UI", size=11, weight="bold")) # Explicitly here for Labelframe labels
        for color_name in ["primary", "info", "success", "warning", "danger"]:
            style.configure(f"{color_name}.TLabelframe", bordercolor=PALETTE[color_name], foreground=PALETTE[color_name])
            style.configure(f"{color_name}.TLabelframe.Label", foreground=PALETTE[color_name])


        # Label styles
        style.configure("TLabel", background=PALETTE["dark"], foreground=PALETTE["text_light"], font=self.font_default)
        style.configure("light.TLabel", background=PALETTE["light"], foreground=PALETTE["text_light"], font=self.font_default) # Labels on light cards
        style.configure("title.TLabel", font=self.font_title, foreground=PALETTE["text_light"])
        style.configure("subtitle.TLabel", font=self.font_subtitle, foreground="#A0AEC0") # Softer text color

        # Notebook (Tabs)
        style.configure("TNotebook", background=PALETTE["dark"], borderwidth=0)
        style.configure("TNotebook.Tab", background=PALETTE["light"], foreground=PALETTE["text_light"], padding=(12, 6), font=self.font_bold)
        style.map("TNotebook.Tab", background=[("selected", PALETTE["primary"])], foreground=[("selected", PALETTE["text_light"])])

        # Scrollbar
        style.configure("TScrollbar", background=PALETTE["light"], bordercolor=PALETTE["dark"], arrowcolor=PALETTE["text_light"], troughcolor=PALETTE["dark"])

        # Entry (Search bar)
        style.configure("TEntry", fieldbackground=PALETTE["light"], foreground=PALETTE["text_light"], insertbackground=PALETTE["text_light"], bordercolor=PALETTE["border"], padding=5, font=self.font_default)

        # Progressbar
        style.configure("TProgressbar", background=PALETTE["primary"], troughcolor=PALETTE["light"])
        style.configure("primary-striped.TProgressbar", background=PALETTE["primary"])


        # Treeview styles
        style.configure("Treeview", background=PALETTE["dark"], foreground=PALETTE["text_light"], 
                        rowheight=25, fieldbackground=PALETTE["dark"], borderwidth=1, relief="solid",
                        bordercolor=PALETTE["border"], font=self.font_default)
        style.configure("Treeview.Heading", font=self.font_treeview_heading, background=PALETTE["light"], 
                        foreground=PALETTE["text_light"], anchor="center", borderwidth=0, relief="flat")
        style.map("Treeview.Heading", background=[("active", PALETTE["info"])])

        # Main window background
        self.app.configure(bg=PALETTE["dark"])


    def _setup_custom_fonts(self):
        # This method is less critical now that tkfont.Font objects are used directly.
        # It can be kept for attempting to make "Inter" available system-wide if desired,
        # but direct usage of tkfont.Font is more reliable for specific widgets.
        try:
            font_dir = Path(__file__).resolve().parent / "assets/fonts"
            default_font_family = "Segoe UI" # Fallback
            if "Inter" in tkfont.families(): # Check if Inter is already available
                default_font_family = "Inter"
            elif (font_dir / "Inter-Regular.ttf").exists():
                 # Attempting to register/use local font files with Tkinter is complex and platform-dependent.
                 # For simplicity, we'll rely on it being installed or use Segoe UI.
                 # If "Inter" is critical, it should be installed on the system.
                 print("Inter font file found locally, but ensure it's installed for Tkinter to use it reliably.")
                 # default_font_family = "Inter" # Tentatively use if found, but might not render

            # Update pre-defined font objects if Inter is preferred and available
            if default_font_family == "Inter":
                self.font_default.config(family="Inter")
                self.font_bold.config(family="Inter")
                self.font_title.config(family="Inter")
                # ... and so on for all other tkfont.Font objects
                print("Attempting to use Inter font.")
            else:
                print("Using Segoe UI as default font.")

            # The app.option_add calls are very global and might be overridden by ttkbootstrap themes
            # or specific widget configurations. It's generally safer to configure fonts
            # directly on widgets or through ttk styles.
            # self.app.option_add("*Font", f"{default_font_family} 10")
            # self.app.option_add("*TButton*Font", f"{default_font_family} 10 bold")
        except Exception as e:
            print(f"Font setup warning: {e}. Using system default fonts.")


    def _setup_main_layout(self):
        self.app.title("🛡️ VulnGuard - Web Security Analyzer")
        self.app.geometry(WINDOW_SIZE)
        self.app.minsize(*MIN_WINDOW_SIZE)

        self.main_container = tb.Frame(self.app, bootstyle="dark")
        self.main_container.pack(fill=BOTH, expand=True)

        self._build_sidebar_navigation() # Sidebar

        self.content_area_frame = tb.Frame(self.main_container, bootstyle="dark") # Main content area
        self.content_area_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=SPACING, pady=SPACING)

        self.pages_cache = {} # To store created page frames
        self._initialize_all_pages()


    def _build_sidebar_navigation(self):
        sidebar_width = 250
        self.sidebar_frame = tb.Frame(self.main_container, bootstyle="dark", width=sidebar_width)
        self.sidebar_frame.pack_propagate(False) # Prevent resizing based on content
        self.sidebar_frame.pack(side=LEFT, fill=Y)

        # Logo and App Title
        logo_title_frame = tb.Frame(self.sidebar_frame, bootstyle="dark")
        logo_title_frame.pack(fill=X, pady=(25, 30), padx=20)
        try:
            logo_path = Path(__file__).resolve().parent / "assets/icons/shield.png"
            if logo_path.exists():
                self._app_logo_image = tb.PhotoImage(file=logo_path).subsample(3,3) # Keep reference
                tb.Label(logo_title_frame, image=self._app_logo_image, bootstyle="inverse-dark").pack(side=LEFT, padx=(0, 10))
            else:
                tb.Label(logo_title_frame, text="🛡️", font=tkfont.Font(family="Segoe UI", size=22), bootstyle="inverse-dark").pack(side=LEFT, padx=(0,10))
        except Exception as e:
            print(f"Logo load error: {e}")
            tb.Label(logo_title_frame, text="🛡️", font=tkfont.Font(family="Segoe UI", size=22), bootstyle="inverse-dark").pack(side=LEFT, padx=(0,10))
        
        tb.Label(logo_title_frame, text="VulnGuard", font=tkfont.Font(family="Segoe UI", size=18, weight="bold"), bootstyle="inverse-dark").pack(side=LEFT)

        # Navigation Section Label
        tb.Label(self.sidebar_frame, text="NAVIGATION", font=self.font_sidebar_label,
                   bootstyle="inverse-dark", foreground="#6D7D93").pack(anchor=W, padx=20, pady=(10, 10))

        self.nav_buttons_map = {}
        nav_items_config = [
            ("dashboard", "Dashboard", "📊", self.show_dashboard_page),
            ("report", "Security Report", "📄", self.show_report_page),
            ("charts", "Analytics", "📈", self.show_charts_page),
            ("logs", "Raw Logs", "📋", self.show_logs_page),
            # ("settings", "Settings", "⚙️", self.show_settings_page), # Placeholder
        ]

        for nav_id, text, icon, command_func in nav_items_config:
            btn_container = tb.Frame(self.sidebar_frame, bootstyle="dark")
            btn_container.pack(fill=X, pady=1, padx=15)
            
            active_indicator_bar = tb.Frame(btn_container, bootstyle="dark", width=4) # For active state
            active_indicator_bar.pack(side=LEFT, fill=Y, padx=(0,5))
            
            nav_button = tb.Button(
                btn_container, text=f" {icon}  {text}", bootstyle="link", width=20, # Using link style for sidebar
                command=lambda cmd=command_func, nid=nav_id: self._navigate_to_page(cmd, nid)
            )
            nav_button.pack(side=LEFT, pady=6, anchor=W)
            # Apply font directly to the button if style configure is not specific enough
            nav_button_style_name = nav_button.winfo_class() # e.g., TButton or custom if bootstyle creates one
            self.app.style.configure(nav_button_style_name, anchor="w", justify="left", font=self.font_sidebar_nav)


            self.nav_buttons_map[nav_id] = {"button_widget": nav_button, "indicator_widget": active_indicator_bar, "container_frame": btn_container}
        
        # Footer (Version)
        footer_container = tb.Frame(self.sidebar_frame, bootstyle="dark")
        footer_container.pack(side=BOTTOM, fill=X, pady=20, padx=20)
        tb.Label(footer_container, text="VulnGuard v1.0.1", font=self.font_sidebar_footer,
                   bootstyle="inverse-dark", foreground="#6D7D93").pack(side=LEFT)


    def _navigate_to_page(self, page_command, nav_id_clicked):
        # Reset style for all nav buttons
        for nav_id, elements in self.nav_buttons_map.items():
            elements["indicator_widget"].configure(bootstyle="dark") # Hide indicator
            elements["container_frame"].configure(bootstyle="dark") # Reset background
            elements["button_widget"].configure(bootstyle="link") # Reset to default link style

        # Highlight the clicked nav button
        self.nav_buttons_map[nav_id_clicked]["indicator_widget"].configure(bootstyle="primary") # Show primary color indicator
        self.nav_buttons_map[nav_id_clicked]["container_frame"].configure(bootstyle="light") # Highlight background
        self.nav_buttons_map[nav_id_clicked]["button_widget"].configure(bootstyle="primary-link") # Emphasize link

        page_command() # Execute the command to show the page


    def _initialize_all_pages(self):
        # Create all page frames but don't pack them yet
        self.pages_cache["welcome"] = self._build_welcome_page_content()
        self.pages_cache["dashboard"] = self._build_dashboard_page_content()
        self.pages_cache["report"] = self._build_report_page_content()
        self.pages_cache["charts"] = self._build_charts_page_content()
        self.pages_cache["logs"] = self._build_logs_page_content()
        # self.pages_cache["settings"] = self._build_settings_page_content() # Placeholder

        for page_frame in self.pages_cache.values():
            page_frame.pack_forget() # Ensure all are hidden initially


    def show_page(self, page_name_to_show):
        if page_name_to_show in self.pages_cache:
            if self.current_page_name and self.current_page_name in self.pages_cache:
                self.pages_cache[self.current_page_name].pack_forget() # Hide current page
            
            self.pages_cache[page_name_to_show].pack(fill=BOTH, expand=True) # Show new page
            self.current_page_name = page_name_to_show
        else:
            print(f"Error: Page '{page_name_to_show}' not found.")

    # Page show methods
    def show_welcome_page(self): self.show_page("welcome")
    def show_dashboard_page(self):
        self.show_page("dashboard")
        if self.data_loaded_successfully and self.current_stats_data:
            self.refresh_dashboard_content(self.current_stats_data) # Refresh if data exists

    def show_report_page(self):
        self.show_page("report")
        # Report content is updated after analysis, or shows placeholder/previous
    
    def show_charts_page(self):
        self.show_page("charts")
        if self.data_loaded_successfully and self.current_stats_data:
            self.display_analytics_charts() # Refresh charts if data exists

    def show_logs_page(self):
        self.show_page("logs")
        self._populate_raw_logs_display() # Load logs when navigating to this page

    # def show_settings_page(self): self.show_page("settings") # Placeholder

    def _build_dashboard_page_content(self):
        page_frame = tb.Frame(self.content_area_frame, bootstyle="dark")

        # Header: Title and Refresh Button
        header_frame = tb.Frame(page_frame, bootstyle="dark")
        header_frame.pack(fill=X, pady=(0, SPACING * 2))
        tb.Label(header_frame, text="Security Dashboard", style="title.TLabel").pack(side=LEFT) # Uses styled font
        refresh_button = tb.Button(header_frame, text="🔄 Refresh Data", 
                                   bootstyle="primary-outline", command=self.trigger_analysis_async)
        refresh_button.pack(side=RIGHT)

        # Main content area for dashboard (stats cards, recent attacks, charts)
        dashboard_main_content = tb.Frame(page_frame, bootstyle="dark")
        dashboard_main_content.pack(fill=BOTH, expand=True)

        # Layout: Two columns for dashboard content
        left_column_frame = tb.Frame(dashboard_main_content, bootstyle="dark")
        left_column_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, SPACING))
        right_column_frame = tb.Frame(dashboard_main_content, bootstyle="dark")
        right_column_frame.pack(side=RIGHT, fill=BOTH, expand=True, padx=(SPACING, 0))

        # Stat Cards Section (in left column)
        stats_cards_grid = tb.Frame(left_column_frame, bootstyle="dark")
        stats_cards_grid.pack(fill=X, pady=(0, SPACING * 2))
        stats_cards_grid.columnconfigure((0, 1, 2), weight=1) # 3 cards per row

        # Store labels for animation
        self.stat_card_labels = {
            "total_requests": self._create_stat_metric_card(stats_cards_grid, 0, 0, "Total Requests", "0", "📊", "primary"),
            "failed_logins": self._create_stat_metric_card(stats_cards_grid, 0, 1, "Failed Logins", "0", "🔒", "danger"),
            "suspicious_ips": self._create_stat_metric_card(stats_cards_grid, 0, 2, "Suspicious IPs", "0", "🌐", "warning"),
            "attack_types_count": self._create_stat_metric_card(stats_cards_grid, 1, 0, "Attack Types Found", "0", "⚔️", "info"),
            "successful_logins": self._create_stat_metric_card(stats_cards_grid, 1, 1, "Successful Logins", "0", "✅", "success"),
            "failed_registrations": self._create_stat_metric_card(stats_cards_grid, 1, 2, "Failed Registrations", "0", "❌", "secondary"),
            "successful_registrations": self._create_stat_metric_card(stats_cards_grid, 2, 0, "Successful Registrations", "0", "👍", "success"), # One more card
        }
        
        # Recent Attacks Panel (in left column, below stats cards)
        attacks_panel_frame = tb.Labelframe(left_column_frame, text="Recent Attack Incidents", 
                                     bootstyle="primary", padding=SPACING)
        attacks_panel_frame.pack(fill=BOTH, expand=True)

        # Search bar for attacks table
        search_bar_frame = tb.Frame(attacks_panel_frame, bootstyle="dark") # Use dark to match Labelframe interior
        search_bar_frame.pack(fill=X, pady=(0, SPACING))
        tb.Label(search_bar_frame, text="Search:", bootstyle="inverse-dark", font=self.font_default).pack(side=LEFT, padx=(0, SPACING))
        self.attacks_search_entry = tb.Entry(search_bar_frame, textvariable=self.search_var, bootstyle="light", font=self.font_default)
        self.attacks_search_entry.pack(side=LEFT, fill=X, expand=True)
        self.search_var.trace_add("write", self.filter_treeview_rows)

        # Treeview for recent attacks
        tree_columns = ("timestamp", "type", "source", "details")
        self.attacks_tree = ttk.Treeview(attacks_panel_frame, columns=tree_columns, show="headings", bootstyle="primary")
        
        for col_name in tree_columns:
            self.attacks_tree.heading(col_name, text=col_name.replace("_", " ").title(), 
                                      command=lambda c=col_name: self.sort_treeview_column(self.attacks_tree, c))
        
        self.attacks_tree.column("timestamp", width=150, anchor="w")
        self.attacks_tree.column("type", width=180, anchor="w")
        self.attacks_tree.column("source", width=130, anchor="w")
        self.attacks_tree.column("details", width=300, anchor="w")

        tree_v_scroll = ttk.Scrollbar(attacks_panel_frame, orient="vertical", command=self.attacks_tree.yview)
        self.attacks_tree.configure(yscrollcommand=tree_v_scroll.set)
        self.attacks_tree.pack(side=LEFT, fill=BOTH, expand=True)
        tree_v_scroll.pack(side=RIGHT, fill=Y)

        # Configure Treeview tags for row styling (colors and hidden_by_filter)
        for attack_name_key, color_val in ROW_COLORS.items():
            self.attacks_tree.tag_configure(attack_name_key, foreground=color_val)
        self.attacks_tree.tag_configure("attack_even_row", background=PALETTE["dark"], foreground=PALETTE["text_light"])
        self.attacks_tree.tag_configure("attack_odd_row", background=PALETTE["light"], foreground=PALETTE["text_light"]) # Zebra
        self.attacks_tree.tag_configure("hidden_by_filter", foreground=PALETTE["dark"], background=PALETTE["dark"]) # Make invisible


        # Charts Section (in right column)
        attack_dist_chart_frame = tb.Labelframe(right_column_frame, text="Attack Distribution", 
                                          bootstyle="info", padding=SPACING)
        attack_dist_chart_frame.pack(fill=BOTH, expand=True, pady=(0, SPACING))
        self.attack_dist_chart_canvas_container = tb.Frame(attack_dist_chart_frame, bootstyle="light") # Container for Matplotlib canvas
        self.attack_dist_chart_canvas_container.pack(fill=BOTH, expand=True)

        login_reg_chart_frame = tb.Labelframe(right_column_frame, text="Login & Registration Attempts", 
                                        bootstyle="success", padding=SPACING)
        login_reg_chart_frame.pack(fill=BOTH, expand=True, pady=(SPACING,0))
        self.login_reg_chart_canvas_container = tb.Frame(login_reg_chart_frame, bootstyle="light") # Container for Matplotlib canvas
        self.login_reg_chart_canvas_container.pack(fill=BOTH, expand=True)

        return page_frame


    def _create_stat_metric_card(self, parent_grid, grid_row, grid_col, card_title, initial_value, icon_char, bootstyle_color):
        """Helper to create a styled statistics card."""
        card_frame = tb.Frame(parent_grid, bootstyle=f"{bootstyle_color}-light", relief="solid", borderwidth=1) # Use themed light style
        card_frame.grid(row=grid_row, column=grid_col, padx=SPACING/2, pady=SPACING/2, sticky="nsew")
        
        card_padding_frame = tb.Frame(card_frame, bootstyle=f"{bootstyle_color}-light") # Inner padding
        card_padding_frame.pack(fill=BOTH, expand=True, padx=SPACING, pady=SPACING)

        header_line = tb.Frame(card_padding_frame, bootstyle=f"{bootstyle_color}-light")
        header_line.pack(fill=X)
        tb.Label(header_line, text=icon_char, font=self.font_stat_card_icon, bootstyle=f"{bootstyle_color}-light").pack(side=LEFT)
        tb.Label(header_line, text=card_title, font=self.font_stat_card_title, bootstyle=f"{bootstyle_color}-light").pack(side=LEFT, padx=(SPACING/2, 0))

        value_display_label = tb.Label(card_padding_frame, text=initial_value, font=self.font_stat_card_value, bootstyle=f"{bootstyle_color}-light")
        value_display_label.pack(pady=(SPACING/2, 0), anchor=W)
        return value_display_label


    def refresh_dashboard_content(self, stats_dict):
        """Updates the dashboard UI elements with new statistics data."""
        if not stats_dict: return

        # Animate stat card values
        self.animate_value(self.stat_card_labels["total_requests"], 
                           int(self.stat_card_labels["total_requests"].cget("text")), stats_dict['total_requests'])
        self.animate_value(self.stat_card_labels["failed_logins"], 
                           int(self.stat_card_labels["failed_logins"].cget("text")), stats_dict['failed_logins'])
        self.animate_value(self.stat_card_labels["suspicious_ips"], 
                           int(self.stat_card_labels["suspicious_ips"].cget("text")), len(stats_dict['suspicious_ips_set']))
        self.animate_value(self.stat_card_labels["attack_types_count"], 
                           int(self.stat_card_labels["attack_types_count"].cget("text")), len(stats_dict['attack_types']))
        self.animate_value(self.stat_card_labels["successful_logins"], 
                           int(self.stat_card_labels["successful_logins"].cget("text")), stats_dict['successful_logins'])
        self.animate_value(self.stat_card_labels["failed_registrations"], 
                           int(self.stat_card_labels["failed_registrations"].cget("text")), stats_dict['failed_registrations'])
        self.animate_value(self.stat_card_labels["successful_registrations"], 
                           int(self.stat_card_labels["successful_registrations"].cget("text")), stats_dict['successful_registrations'])


        # Update Recent Attacks Treeview
        for item in self.attacks_tree.get_children(): self.attacks_tree.delete(item) # Clear old items
        
        # Sort attacks by timestamp (descending for recent first) before displaying a slice
        def get_sort_key_tree(attack_item):
            ts = attack_item.get('timestamp')
            if isinstance(ts, str) and ts:
                try: return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                except ValueError: return datetime.min 
            return datetime.min
        
        # Show last N attacks, most recent first
        recent_attacks_to_show = sorted(stats_dict.get('potential_attacks', []), key=get_sort_key_tree, reverse=True)[:25]

        for i, attack_data in enumerate(recent_attacks_to_show):
            ts = attack_data.get('timestamp', 'N/A')
            attack_type_title = attack_data.get('type', 'Unknown') # Already title-cased
            source_ip = attack_data.get('ip', 'N/A')
            source_user = attack_data.get('username')
            source_display = f"{source_ip}" + (f" ({source_user})" if source_user else "")
            details_text = attack_data.get('details', '')

            # Determine tag for coloring: specific attack type or alternating row color
            row_tag = attack_type_title if attack_type_title in ROW_COLORS else (f"attack_even_row" if i % 2 == 0 else f"attack_odd_row")
            
            self.attacks_tree.insert("", "end", values=(ts, attack_type_title, source_display, details_text), tags=(row_tag,))

        # Update Dashboard Charts
        self._display_attack_distribution_pie_chart(stats_dict, self.attack_dist_chart_canvas_container)
        self._display_login_registration_bar_chart(stats_dict, self.login_reg_chart_canvas_container)


    def _display_matplotlib_chart_on_canvas(self, fig, canvas_container_widget):
        """Helper to embed a Matplotlib figure onto a Tkinter Frame."""
        for widget in canvas_container_widget.winfo_children(): widget.destroy() # Clear previous
        
        canvas = FigureCanvasTkAgg(fig, master=canvas_container_widget)
        canvas.draw()
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill=BOTH, expand=True)
        plt.close(fig) # Close the figure to free memory


    def _display_attack_distribution_pie_chart(self, stats_data, canvas_container):
        fig, ax = plt.subplots(figsize=(8, 6)) # Adjust size as needed
        fig.patch.set_facecolor(PALETTE["light"]) # Match container background

        if stats_data['attack_types']:
            labels = [k.replace('_', ' ').title() for k in stats_data['attack_types'].keys()]
            sizes = list(stats_data['attack_types'].values())
            chart_colors = [ROW_COLORS.get(label, PALETTE["info"]) for label in labels]
            explode = [0.03] * len(sizes)

            wedges, texts, autotexts = ax.pie(
                sizes, explode=explode, labels=labels, colors=chart_colors,
                autopct='%1.1f%%', shadow=False, startangle=140,
                wedgeprops={'edgecolor': PALETTE["border"], 'linewidth': 1},
                textprops={'color': PALETTE["text_light"], 'fontsize': 9, 'fontweight':'bold'}
            )
            for autotext in autotexts: autotext.set_color(PALETTE["text_dark"]) # Darker text on slices

            ax.axis('equal') # Equal aspect ratio ensures that pie is drawn as a circle.
            # ax.set_title('Attack Type Distribution', color=PALETTE["text_light"], fontsize=14, pad=15)
        else:
            ax.text(0.5, 0.5, 'No Attack Data', fontsize=14, ha='center', va='center', color=PALETTE["text_light"])
            ax.axis('off')
        
        self._display_matplotlib_chart_on_canvas(fig, canvas_container)


    def _display_login_registration_bar_chart(self, stats_data, canvas_container):
        fig, ax = plt.subplots(figsize=(8, 4)) # Adjust size
        fig.patch.set_facecolor(PALETTE["light"])

        categories = ['Successful', 'Failed']
        login_counts = [stats_data['successful_logins'], stats_data['failed_logins']]
        reg_counts = [stats_data['successful_registrations'], stats_data['failed_registrations']]

        if sum(login_counts) == 0 and sum(reg_counts) == 0:
            ax.text(0.5, 0.5, 'No Login/Registration Data', fontsize=14, ha='center', va='center', color=PALETTE["text_light"])
            ax.axis('off')
        else:
            x_indices = range(len(categories))
            bar_width = 0.35
            
            ax.bar([i - bar_width/2 for i in x_indices], login_counts, bar_width, 
                   label='Logins', color=PALETTE["primary"])
            ax.bar([i + bar_width/2 for i in x_indices], reg_counts, bar_width, 
                   label='Registrations', color=PALETTE["secondary"])

            ax.set_ylabel('Count', color=PALETTE["text_light"])
            # ax.set_title('Login & Registration Attempts', color=PALETTE["text_light"], fontsize=14)
            ax.set_xticks(x_indices)
            ax.set_xticklabels(categories, color=PALETTE["text_light"])
            ax.tick_params(axis='y', colors=PALETTE["text_light"])
            ax.legend(facecolor=PALETTE["light"], edgecolor=PALETTE["border"], labelcolor=PALETTE["text_light"])
            ax.grid(axis='y', linestyle='--', alpha=0.3, color=PALETTE["border"])
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.spines['bottom'].set_color(PALETTE["border"])
            ax.spines['left'].set_color(PALETTE["border"])

        self._display_matplotlib_chart_on_canvas(fig, canvas_container)


    def _build_welcome_page_content(self):
        page_frame = tb.Frame(self.content_area_frame, bootstyle="dark")
        center_content_frame = tb.Frame(page_frame, bootstyle="dark")
        center_content_frame.place(relx=0.5, rely=0.5, anchor="center")

        try:
            large_logo_path = Path(__file__).resolve().parent / "assets/icons/shield-large.png"
            if large_logo_path.exists():
                self._welcome_logo_img = tb.PhotoImage(file=large_logo_path) # Keep ref
                tb.Label(center_content_frame, image=self._welcome_logo_img, bootstyle="inverse-dark").pack(pady=(0, 20))
            else:
                 tb.Label(center_content_frame, text="🛡️", font=self.font_welcome_icon, foreground=PALETTE["primary"], bootstyle="inverse-dark").pack(pady=(0, 20))
        except Exception as e:
            print(f"Welcome logo error: {e}")
            tb.Label(center_content_frame, text="🛡️", font=self.font_welcome_icon, foreground=PALETTE["primary"], bootstyle="inverse-dark").pack(pady=(0, 20))
        
        tb.Label(center_content_frame, text="Welcome to VulnGuard", font=self.font_welcome_title, bootstyle="inverse-dark").pack()
        tb.Label(center_content_frame, text="Advanced Web Security Log Analysis Tool", font=self.font_welcome_subtitle, 
                   foreground="#A0AEC0", bootstyle="inverse-dark").pack(pady=(5, 30))
        
        start_analysis_button = tb.Button(center_content_frame, text="🚀 Start Analysis", 
                                         bootstyle="success", width=20, command=self._initiate_analysis_from_welcome)
        start_analysis_button.pack(pady=10, ipady=5) # ipady for internal padding

        tb.Label(center_content_frame, text="Version 1.0.1", font=self.font_welcome_version, 
                   foreground="#6D7D93", bootstyle="inverse-dark").pack(pady=(30, 0))
        return page_frame

    def _initiate_analysis_from_welcome(self):
        self._navigate_to_page(self.show_dashboard_page, "dashboard") # Switch to dashboard visually
        self.trigger_analysis_async() # Then start analysis


    def trigger_analysis_async(self):
        """Initiates the log analysis process asynchronously with a progress indicator."""
        if hasattr(self, 'progress_overlay_frame') and self.progress_overlay_frame.winfo_exists():
            self.progress_overlay_frame.destroy() # Remove old one if exists

        self.progress_overlay_frame = tb.Frame(self.app, bootstyle="dark") # Use app as parent for overlay
        self.progress_overlay_frame.place(relx=0.5, rely=0.5, anchor="center", bordermode="outside") # Center on app

        loading_content_frame = tb.Frame(self.progress_overlay_frame, bootstyle="light", padding=20) # Inner styled frame
        loading_content_frame.pack()

        tb.Label(loading_content_frame, text="🔬 Analyzing Security Logs...", 
                   font=self.font_loading_title, bootstyle="light").pack(pady=(0, SPACING))
        
        self.analysis_progress_bar = ttk.Progressbar(loading_content_frame, orient="horizontal", length=350, 
                                               mode="determinate", bootstyle="success-striped", maximum=100)
        self.analysis_progress_bar.pack(pady=(0, SPACING))
        self.analysis_progress_bar.start() # For indeterminate animation initially

        self.analysis_status_label = tb.Label(loading_content_frame, text="Initializing...", 
                                        font=self.font_loading_status, bootstyle="light")
        self.analysis_status_label.pack(pady=(0, SPACING))

        # Disable interaction with other parts of the GUI (optional, can be complex)
        # self.app.grab_set() # Makes the progress_overlay modal

        threading.Thread(target=self._execute_analysis_steps, daemon=True).start()


    def _execute_analysis_steps(self):
        """Runs the actual analysis, updating progress bar and status label."""
        try:
            analysis_steps = [
                ("Reading log files...", 10, 0.1),
                ("Parsing log entries...", 30, 0.3),
                ("Detecting attack patterns...", 60, 0.5),
                ("Aggregating suspicious activities...", 80, 0.2),
                ("Generating report data...", 95, 0.1),
                ("Finalizing analysis...", 100, 0.1)
            ]
            self.app.after(0, lambda: self.analysis_progress_bar.config(mode="determinate"))

            for status_text, progress_value, sleep_duration in analysis_steps:
                self.app.after(0, lambda s=status_text: self.analysis_status_label.config(text=s))
                self.app.after(0, lambda p=progress_value: self.analysis_progress_bar.config(value=p))
                time.sleep(sleep_duration) # Simulate work for this step

            # Perform the actual analysis
            self.current_stats_data = self.analyzer.parse_logs()
            # Generate visualization files (can be done here or on demand)
            self.analyzer._generate_visualization_files(self.current_stats_data)
            # Generate attacker reports file
            self.analyzer.generate_attacker_reports(self.current_stats_data)


            self.data_loaded_successfully = True
            self.app.after(0, self._on_analysis_complete_ui_update)
            self.app.after(0, lambda: messagebox.showinfo("Analysis Complete", "Security log analysis finished successfully."))

        except Exception as e:
            self.data_loaded_successfully = False
            print(f"Analysis Error: {e}")
            self.app.after(0, lambda: messagebox.showerror("Analysis Error", f"An error occurred: {e}"))
        finally:
            if hasattr(self, 'progress_overlay_frame') and self.progress_overlay_frame.winfo_exists():
                self.app.after(0, self.progress_overlay_frame.destroy)
            # self.app.grab_release() # Release modal grab if set


    def _on_analysis_complete_ui_update(self):
        """Updates the UI elements after analysis is complete. Called from main thread."""
        if self.data_loaded_successfully and self.current_stats_data:
            # Update the textual report in the Report Page
            report_content_str = self.analyzer.generate_report() # This uses the latest parse from analyzer
            self.report_display_text.config(state="normal")
            self.report_display_text.delete(1.0, "end")
            self.report_display_text.insert("end", report_content_str)
            self.report_display_text.config(state="disabled")

            # Refresh dashboard if it's the current page (or will be shown next)
            if self.current_page_name == "dashboard":
                self.refresh_dashboard_content(self.current_stats_data)
            
            # Refresh charts page if it's current
            if self.current_page_name == "charts":
                self.display_analytics_charts()
        else:
            # Handle analysis failure or no data
            self.report_display_text.config(state="normal")
            self.report_display_text.delete(1.0, "end")
            self.report_display_text.insert("end", "Analysis failed or no data was processed.")
            self.report_display_text.config(state="disabled")
            # Optionally clear or show "No Data" on dashboard/charts
            empty_stats = {
                'total_requests': 0, 'failed_logins': 0, 'successful_logins': 0,
                'failed_registrations': 0, 'successful_registrations': 0,
                'suspicious_ips_set': set(), 'attack_types': defaultdict(int),
                'potential_attacks': []
            }
            if self.current_page_name == "dashboard": self.refresh_dashboard_content(empty_stats)
            if self.current_page_name == "charts": self.display_analytics_charts() # Will show "No Data" if stats are empty


    def _build_report_page_content(self):
        page_frame = tb.Frame(self.content_area_frame, bootstyle="dark")

        controls_frame = tb.Frame(page_frame, bootstyle="dark")
        controls_frame.pack(fill=X, padx=SPACING, pady=SPACING)
        tb.Button(controls_frame, text="🔍 Re-Analyze & Generate Report", 
                  bootstyle="primary-outline", command=self.trigger_analysis_async).pack(side=LEFT)
        # Add button to open attacker reports file?
        tb.Button(controls_frame, text="📂 View Attacker Reports Dir", 
                  bootstyle="info-outline", command=self._open_attacker_reports_directory).pack(side=LEFT, padx=SPACING)


        report_content_container = tb.Frame(page_frame, bootstyle="light", padding=SPACING) # Light background for text
        report_content_container.pack(fill=BOTH, expand=True, padx=SPACING, pady=(0, SPACING))

        self.report_display_text = scrolledtext.ScrolledText(
            report_content_container, wrap="word", font=self.font_scrolled_text, 
            bg=PALETTE["light"], fg=PALETTE["text_dark"], # Dark text on light background
            insertbackground=PALETTE["primary"], borderwidth=0, relief='flat',
            padx=10, pady=10
        )
        self.report_display_text.pack(fill=BOTH, expand=True)
        self.report_display_text.insert("end", "Click 'Re-Analyze' to generate the security report.")
        self.report_display_text.config(state="disabled")
        self.report_display_text.bind("<Control-c>", lambda e: self.app.clipboard_clear() or self.app.clipboard_append(self.report_display_text.selection_get()) or "break")
        return page_frame
    
    def _open_attacker_reports_directory(self):
        reports_dir = Path('data/attacker_reports').resolve()
        try:
            if reports_dir.exists():
                # Platform-specific way to open directory
                import os, platform
                if platform.system() == "Windows":
                    os.startfile(reports_dir)
                elif platform.system() == "Darwin": # macOS
                    os.system(f"open \"{reports_dir}\"")
                else: # Linux and other UNIX-like
                    os.system(f"xdg-open \"{reports_dir}\"")
            else:
                messagebox.showinfo("Directory Not Found", f"The directory {reports_dir} does not exist yet. Run analysis to create it.")
        except Exception as e:
            messagebox.showerror("Error Opening Directory", f"Could not open directory: {e}")


    def _build_charts_page_content(self):
        page_frame = tb.Frame(self.content_area_frame, bootstyle="dark")
        
        controls_frame = tb.Frame(page_frame, bootstyle="dark")
        controls_frame.pack(fill=X, padx=SPACING, pady=SPACING)
        tb.Button(controls_frame, text="🔄 Refresh Analytics Data", 
                  bootstyle="primary-outline", command=self.trigger_analysis_async).pack(side=LEFT)

        self.charts_display_area = tb.Frame(page_frame, bootstyle="dark") # Main container for charts
        self.charts_display_area.pack(fill=BOTH, expand=True, padx=SPACING, pady=(0,SPACING))
        
        # Configure grid for charts (e.g., 2x2 or 1x3)
        self.charts_display_area.columnconfigure(0, weight=1)
        self.charts_display_area.columnconfigure(1, weight=1) # Two columns
        self.charts_display_area.rowconfigure(0, weight=1)
        self.charts_display_area.rowconfigure(1, weight=1) # Two rows (for up to 4 charts)

        # Placeholders for chart canvases (will be populated by display_analytics_charts)
        # These are just frames where Matplotlib canvases will be embedded.
        self.chart_canvas_1_container = tb.Labelframe(self.charts_display_area, text="Attack Distribution", bootstyle="info", padding=SPACING)
        self.chart_canvas_1_container.grid(row=0, column=0, sticky="nsew", padx=SPACING/2, pady=SPACING/2)
        
        self.chart_canvas_2_container = tb.Labelframe(self.charts_display_area, text="Login Attempts", bootstyle="success", padding=SPACING)
        self.chart_canvas_2_container.grid(row=0, column=1, sticky="nsew", padx=SPACING/2, pady=SPACING/2)

        self.chart_canvas_3_container = tb.Labelframe(self.charts_display_area, text="Registration Attempts", bootstyle="warning", padding=SPACING)
        self.chart_canvas_3_container.grid(row=1, column=0, sticky="nsew", padx=SPACING/2, pady=SPACING/2)
        
        # self.chart_canvas_4_container = tb.Labelframe(self.charts_display_area, text="Future Chart", bootstyle="secondary", padding=SPACING)
        # self.chart_canvas_4_container.grid(row=1, column=1, sticky="nsew", padx=SPACING/2, pady=SPACING/2)

        return page_frame

    def display_analytics_charts(self):
        """Populates the charts page with visualizations from saved files or by regenerating."""
        if not self.data_loaded_successfully or not self.current_stats_data:
            # Display "No data" messages on chart containers
            for container in [self.chart_canvas_1_container, self.chart_canvas_2_container, self.chart_canvas_3_container]:
                for widget in container.winfo_children(): widget.destroy() # Clear previous content
                # Ensure the label inside Labelframe uses a font that contrasts with its "light" background
                no_data_font = tkfont.Font(family="Segoe UI", size=12) # Example font
                tb.Label(container, text="No data available. Please run analysis.", 
                         font=no_data_font, bootstyle="inverse-light", anchor="center").pack(fill=BOTH, expand=True)
            return

        # Use the stats data to generate charts directly onto the canvases
        self._display_attack_distribution_pie_chart(self.current_stats_data, self.chart_canvas_1_container)
        self._display_login_attempts_on_analytics_page(self.current_stats_data, self.chart_canvas_2_container)
        self._display_registration_attempts_on_analytics_page(self.current_stats_data, self.chart_canvas_3_container)

    def _display_login_attempts_on_analytics_page(self, stats_data, canvas_container):
        fig, ax = plt.subplots(figsize=(6,4))
        fig.patch.set_facecolor(PALETTE["light"])
        if stats_data['successful_logins'] > 0 or stats_data['failed_logins'] > 0:
            ax.bar(['Successful', 'Failed'], [stats_data['successful_logins'], stats_data['failed_logins']],
                   color=[PALETTE["success"], PALETTE["danger"]])
            ax.set_ylabel('Count', color=PALETTE["text_light"])
            ax.tick_params(axis='x', colors=PALETTE["text_light"])
            ax.tick_params(axis='y', colors=PALETTE["text_light"])
            ax.grid(axis='y', linestyle='--', alpha=0.3, color=PALETTE["border"])
        else:
            ax.text(0.5, 0.5, 'No Login Data', ha='center', va='center', color=PALETTE["text_light"])
            ax.axis('off')
        self._display_matplotlib_chart_on_canvas(fig, canvas_container)

    def _display_registration_attempts_on_analytics_page(self, stats_data, canvas_container):
        fig, ax = plt.subplots(figsize=(6,4))
        fig.patch.set_facecolor(PALETTE["light"])
        if stats_data['successful_registrations'] > 0 or stats_data['failed_registrations'] > 0:
            ax.bar(['Successful', 'Failed'], [stats_data['successful_registrations'], stats_data['failed_registrations']],
                   color=[PALETTE["success"], PALETTE["danger"]])
            ax.set_ylabel('Count', color=PALETTE["text_light"])
            ax.tick_params(axis='x', colors=PALETTE["text_light"])
            ax.tick_params(axis='y', colors=PALETTE["text_light"])
            ax.grid(axis='y', linestyle='--', alpha=0.3, color=PALETTE["border"])
        else:
            ax.text(0.5, 0.5, 'No Registration Data', ha='center', va='center', color=PALETTE["text_light"])
            ax.axis('off')
        self._display_matplotlib_chart_on_canvas(fig, canvas_container)


    def _build_logs_page_content(self):
        page_frame = tb.Frame(self.content_area_frame, bootstyle="dark")
        
        tb.Label(page_frame, text="Raw Web Logs (Weblogs.csv)", style="title.TLabel", anchor="w").pack(fill=X, pady=(0, SPACING))
        
        log_display_container = tb.Frame(page_frame, bootstyle="light", padding=SPACING)
        log_display_container.pack(fill=BOTH, expand=True, pady=(0, SPACING))

        self.raw_logs_display_text = scrolledtext.ScrolledText(
            log_display_container, wrap="none", font=self.font_raw_logs, 
            bg=PALETTE["light"], fg=PALETTE["text_dark"],
            insertbackground=PALETTE["primary"], borderwidth=0, relief='flat',
            padx=5, pady=5
        )
        self.raw_logs_display_text.pack(fill=BOTH, expand=True)
        self.raw_logs_display_text.insert("end", "Raw logs will be displayed here...")
        self.raw_logs_display_text.config(state="disabled")
        
        # Button to reload logs (though it loads on page show)
        tb.Button(page_frame, text="🔄 Reload Logs from File", bootstyle="info-outline", 
                  command=self._populate_raw_logs_display).pack(pady=SPACING, anchor="e")
        return page_frame

    def _populate_raw_logs_display(self):
        """Loads and displays content from data/Weblogs.csv."""
        log_file = Path('data/Weblogs.csv')
        self.raw_logs_display_text.config(state="normal")
        self.raw_logs_display_text.delete(1.0, "end")
        if log_file.exists():
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    # Read in chunks if file is very large, for now read all
                    content = f.read(2 * 1024 * 1024) # Limit to 2MB for display to avoid freezing
                    self.raw_logs_display_text.insert("end", content)
                    if len(content) == 2 * 1024 * 1024 :
                         self.raw_logs_display_text.insert("end", "\n\n--- Log display truncated due to size ---")
            except Exception as e:
                self.raw_logs_display_text.insert("end", f"Error reading log file: {e}")
        else:
            self.raw_logs_display_text.insert("end", f"Log file not found: {log_file.resolve()}")
        self.raw_logs_display_text.config(state="disabled")


    def _bind_global_events(self):
        # self.app.bind("<Configure>", self._on_window_resize_event) # If needed
        self.app.bind("<Control-r>", lambda e: self.trigger_analysis_async()) # Ctrl+R to refresh/re-analyze
        self.app.bind("<Control-q>", lambda e: self.app.quit()) # Ctrl+Q to quit

    # Placeholder for future methods or event handlers
    # def _on_window_resize_event(self, event): pass
    # def _build_settings_page_content(self):
    #     page_frame = tb.Frame(self.content_area_frame, bootstyle="dark")
    #     tb.Label(page_frame, text="Settings (Coming Soon)", style="title.TLabel").pack(pady=20)
    #     return page_frame


if __name__ == "__main__":
    # Ensure 'data' directory exists for logs and reports
    Path('data').mkdir(exist_ok=True)
    
    # Create dummy Weblogs.csv if it doesn't exist for testing
    dummy_log_path = Path('data/Weblogs.csv')
    if not dummy_log_path.exists():
        with open(dummy_log_path, 'w', encoding='utf-8') as f:
            f.write("+-+-+-\n")
            f.write("Name: testuser\n")
            f.write("Date Login: 2023-10-26 10:00:00\n")
            f.write("IP Address: 192.168.1.100\n")
            f.write("Login Status: Failed\n")
            f.write("Process Type: Not matched data\n")
            f.write("+-+-+-\n")
            f.write("Name: attacker\n")
            f.write("Date Login: 2023-10-26 10:01:00\n")
            f.write("IP Address: 10.0.0.5\n")
            f.write("Login Status: Failed\n")
            f.write("User Agent: <script>alert('xss')</script>\n") # XSS attempt
            f.write("Process Type: Matched data\n")
            f.write("+-+-+-\n")
            f.write("Name: admin\n")
            f.write("Date Register: 2023-10-26 10:05:00\n")
            f.write("IP Address: 10.0.0.5\n")
            f.write("Register Status: Failed\n") # Failed registration
            f.write("Details: Attempt from known malicious IP\n")
            f.write("+-+-+-\n")
    
    # Create dummy reports.txt if it doesn't exist
    dummy_report_txt_path = Path('data/reports.txt')
    if not dummy_report_txt_path.exists():
        with open(dummy_report_txt_path, 'w', encoding='utf-8') as f:
            f.write("IP Address: 1.2.3.4\n")
            f.write("Reason: Known attacker\n")
            f.write("--\n") # Delimiter

    app = tb.Window(themename=DARK_THEME_NAME) # Use ttkbootstrap Window
    gui_instance = LogAnalyzerGUI(app)
    app.mainloop()
