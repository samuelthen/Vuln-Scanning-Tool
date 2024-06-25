import re
import logging
import requests
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from src.passive_scan.passive_scan_rules.utils.alert import Alert

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

class PathTraversalScanRule:
    VALID_ATTACK_STRENGTH = {"LOW", "MEDIUM", "HIGH", "INSANE"}

    def __init__(self, attack_strength="LOW"):
        if attack_strength.upper() not in self.VALID_ATTACK_STRENGTH:
            raise ValueError(f"Invalid risk category '{attack_strength}'. Valid options are: {self.VALID_ATTACK_STRENGTH}")
        
        self.attack_strength = attack_strength.upper()
        self.scope = {
            'Windows': True,
            'Linux': True,
            'MacOS': False,
            'Tomcat': True
        }

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
        "file:///d:\\Windows/system.ini",
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
    
    def get_cwe_id(self):
        return 22
    
    def get_wasc_id(self):
        return 33
    
    ALERT = []

    def scan(self, base_url, param, method="GET"):
        try:
            self.ALERT.clear()
            nix_count, win_count, dir_count, local_traversal_length, include_null_byte_injection_payload = self.get_attack_parameters(self.attack_strength)
            
            logger.debug(f"Attacking at Attack Strength: {self.attack_strength}")
            logger.debug(f"Checking parameter [{param}] for Path Traversal to local files")
            
            if self.scope["Windows"]:
                self.check_file_targets(base_url, param, self.WIN_LOCAL_FILE_TARGETS, self.WIN_PATTERN, win_count, include_null_byte_injection_payload, 1, method)
            
            if self.scope["Linux"] or self.scope["MacOS"]:
                self.check_file_targets(base_url, param, self.NIX_LOCAL_FILE_TARGETS, self.NIX_PATTERN, nix_count, include_null_byte_injection_payload, 2, method)
            
            self.check_directory_targets(base_url, param, dir_count, method)
            
            if self.scope["Tomcat"]:
                self.check_web_app_files(base_url, param, local_traversal_length, method)
            
            self.check_url_filename_traversal(base_url, param, method)

            return self.ALERT                
        except Exception as e:
            logger.warning(f"An error occurred while checking parameter [{param}] for Path Traversal. Caught {e.__class__.__name__} {e}")
    
    def get_attack_parameters(self, attack_strength):
        if attack_strength == "LOW":
            return 2, 2, 2, 0, False
        elif attack_strength == "MEDIUM":
            return 2, 4, 4, 1, False
        elif attack_strength == "HIGH":
            return 4, 8, 7, 2, False
        elif attack_strength == "INSANE":
            return len(self.NIX_LOCAL_FILE_TARGETS), len(self.WIN_LOCAL_FILE_TARGETS), len(self.LOCAL_DIR_TARGETS), 4, True
    
    def check_file_targets(self, base_url, param, targets, pattern, count, include_null_byte_injection_payload, check, method):
        for h in range(count):
            if self.send_and_check_payload(base_url, param, targets[h], pattern, check, method):
                return
            
            if include_null_byte_injection_payload:
                if self.send_and_check_payload(base_url, param, targets[h] + '\x00', pattern, check, method):
                    return
                if self.send_and_check_payload(base_url, param, f"{targets[h]}\x00", pattern, check, method):
                    return
    
    def check_directory_targets(self, base_url, param, dir_count, method):
        for h in range(dir_count):
            if self.send_and_check_payload(base_url, param, self.LOCAL_DIR_TARGETS[h], self.DIR_PATTERN, 3, method):
                return
    
    def check_web_app_files(self, base_url, param, local_traversal_length, method):
        sslash_pattern = "WEB-INF/web.xml"
        bslash_pattern = sslash_pattern.replace('/', '\\')
        
        for _ in range(local_traversal_length):
            if any(
                self.send_and_check_payload(base_url, param, pattern, self.WAR_PATTERN, 4, method)
                for pattern in [sslash_pattern, bslash_pattern, '/' + sslash_pattern, '\\' + bslash_pattern]
            ):
                return
            
            sslash_pattern = "../" + sslash_pattern
            bslash_pattern = "..\\" + bslash_pattern
    
    def check_url_filename_traversal(self, base_url, param, method):
        msg = self.get_new_msg(base_url, method)
        self.set_parameter(msg, param, self.NON_EXISTANT_FILENAME)
        try:
            self.send_and_receive(msg)
        except Exception as ex:
            logger.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
            return
        
        error_pattern = re.compile("Exception|Error", re.IGNORECASE)
        error_matcher = error_pattern.search(msg.response.text)
        urlfilename = urlparse(msg.url).path.split("/")[-1]
        
        if urlfilename and (not self.is_page_200(msg) or error_matcher):
            logger.debug(f"It is possible to check for local file Path Traversal on the url filename on [{msg.method}] [{msg.url}], [{param}]")
            
            for prefix in self.LOCAL_FILE_RELATIVE_PREFIXES:
                
                prefixed_urlfilename = prefix + urlfilename
                msg = self.get_new_msg(base_url, method)
                self.set_parameter(msg, param, prefixed_urlfilename)
                
                try:
                    self.send_and_receive(msg)
                except Exception as ex:
                    logger.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
                    continue
                
                error_matcher = error_pattern.search(msg.response.text)
                if self.is_page_200(msg) and not error_matcher:
                    return self.create_unmatched_alert(param, prefixed_urlfilename, method)
    
    def send_and_check_payload(self, base_url, param, new_value, contents_matcher, check, method):
        msg = self.get_new_msg(base_url, method)
        self.set_parameter(msg, param, new_value)
        
        logger.debug(f"Checking parameter [{param}] for Path Traversal (local file) with value [{new_value}]")
        
        try:
            self.send_and_receive(msg)
        except Exception as ex:
            logger.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
            return False
        
        match = contents_matcher.search(msg.response.text)
        if self.is_page_200(msg) and match:
            self.create_matched_alert(param, new_value, match.group(), check, method)
            return True
        return False
    
    def get_new_msg(self, base_url, method):
        return requests.Request(method, base_url)
    
    def send_and_receive(self, msg):
        prepared = msg.prepare()
        with requests.Session() as session:
            response = session.send(prepared)
            msg.response = response
        return response
    
    def set_parameter(self, msg, param, value):
        if msg.method == 'GET':
            url_parts = list(urlparse(msg.url))
            query = dict(parse_qs(url_parts[4]))
            query[param] = [value]
            url_parts[4] = urlencode(query, doseq=True)
            msg.url = urlunparse(url_parts)
        elif msg.method == 'POST':
            if msg.data is None:
                msg.data = {}
            elif isinstance(msg.data, str):
                msg.data = parse_qs(msg.data)
            msg.data[param] = value
        msg.prepare()

    def is_page_200(self, msg):
        return msg.response.status_code == 200
    
    def create_unmatched_alert(self, param, attack, method):
        self.ALERT.append(str(Alert(risk_category="High", 
                                    msg_ref="ascanrules.pathtraversal",
                                    param=param,
                                    attack=attack,
                                    method=method)))
    
    def create_matched_alert(self, param, attack, evidence, check, method):
        self.ALERT.append(str(Alert(risk_category="High", 
                                    msg_ref=f"https://testportal.helium.sh/mod.php?kategori={attack}", 
                                    param=param,
                                    attack=attack,
                                    evidence=evidence,
                                    method=method)))
