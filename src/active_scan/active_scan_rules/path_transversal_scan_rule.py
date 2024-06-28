import logging.config
import re
import logging
import requests
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
from requests.models import Request, Response
from src.passive_scan.passive_scan_rules.utils.alert import Alert

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.WARNING)

class PathTraversalScanRule:
    VALID_ATTACK_STRENGTH = {"LOW", "MEDIUM", "HIGH", "INSANE"}

    def __init__(self, attack_strength="LOW"):
        attack_strength = attack_strength.upper()
        if attack_strength not in self.VALID_ATTACK_STRENGTH:
            raise ValueError(f"Invalid attack strength '{attack_strength}'. Valid options are: {self.VALID_ATTACK_STRENGTH}")
        self.attack_strength = attack_strength
        self.scope = {
            'Windows': True,
            'Linux': True,
            'MacOS': False,
            'Tomcat': True
        }

    NON_EXISTENT_FILENAME = "thishouldnotexistandhopefullyitwillnot"
    
    WIN_PATTERN = re.compile(r"\[drivers\]")
    WIN_LOCAL_FILE_TARGETS = [
        "c:/Windows/system.ini",
        "../../../../../../../../../../../../../../../../Windows/system.ini",
        "c:\\Windows\\system.ini",
        "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
        "/../../../../../../../../../../../../../../../../Windows/system.ini",
        "\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\system.ini",
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
        "file:\\\\\\d:\\Windows/system.ini",
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
    
    ALERTS = []

    def scan(self, base_url, param, value=None, method="GET"):
        try:
            self.ALERTS.clear()
            attack_params = self.get_attack_parameters(self.attack_strength)
            
            logger.debug(f"Attacking with Attack Strength: {self.attack_strength}")
            logger.debug(f"Checking parameter [{param}] for Path Traversal to local files")
            
            if self.scope["Windows"]:
                self.check_targets(base_url, param, self.WIN_LOCAL_FILE_TARGETS, self.WIN_PATTERN, attack_params[1], attack_params[4], 1, method, value)
            
            if self.scope["Linux"] or self.scope["MacOS"]:
                self.check_targets(base_url, param, self.NIX_LOCAL_FILE_TARGETS, self.NIX_PATTERN, attack_params[0], attack_params[4], 2, method, value)
            
            self.check_directory_targets(base_url, param, attack_params[2], method)
            
            if self.scope["Tomcat"]:
                self.check_web_app_files(base_url, param, attack_params[3], method)
            
            self.check_url_filename_traversal(base_url, param, method)

            return self.ALERTS                
        except Exception as e:
            logger.warning(f"An error occurred while checking parameter [{param}] for Path Traversal. Caught {e.__class__.__name__} {e}")
    
    def get_attack_parameters(self, attack_strength):
        parameters = {
            "LOW": (2, 2, 2, 0, False),
            "MEDIUM": (2, 4, 4, 1, False),
            "HIGH": (4, 8, 7, 2, False),
            "INSANE": (len(self.NIX_LOCAL_FILE_TARGETS), len(self.WIN_LOCAL_FILE_TARGETS), len(self.LOCAL_DIR_TARGETS), 4, True)
        }
        return parameters[attack_strength]
    
    def check_targets(self, base_url, param, targets, pattern, count, include_null_byte, check, method, value=None):
        extension = None
        if self.attack_strength == "INSANE" and value:
            index = value.rfind('.')
            if index != -1:
                extension = value[index:]
        
        for h in range(count):
            logger.debug(f"Sending payload {targets[h]}")
            if self.send_and_check_payload(base_url, param, targets[h], pattern, check, method):
                return
            
            if include_null_byte:
                payloads = [targets[h] + '\x00', targets[h] + '\x00' + (extension or "")]
                for payload in payloads:
                    logger.debug(f"Sending payload with null byte injection: {payload}")
                    if self.send_and_check_payload(base_url, param, payload, pattern, check, method):
                        return
    
    def check_directory_targets(self, base_url, param, dir_count, method):
        for h in range(dir_count):
            logger.debug(f"Sending directory payload {self.LOCAL_DIR_TARGETS[h]}")
            if self.send_and_check_payload(base_url, param, self.LOCAL_DIR_TARGETS[h], self.DIR_PATTERN, 3, method):
                return
    
    def check_web_app_files(self, base_url, param, local_traversal_length, method):
        sslash_pattern = "WEB-INF/web.xml"
        bslash_pattern = sslash_pattern.replace('/', '\\')
        
        for _ in range(local_traversal_length):
            for pattern in [sslash_pattern, bslash_pattern, '/' + sslash_pattern, '\\' + bslash_pattern]:
                if self.send_and_check_payload(base_url, param, pattern, self.WAR_PATTERN, 4, method):
                    return
            sslash_pattern = "../" + sslash_pattern
            bslash_pattern = "..\\" + sslash_pattern
    
    def check_url_filename_traversal(self, base_url, param, method):
        msg = self.get_new_msg(base_url, method)
        self.set_parameter(msg, param, self.NON_EXISTENT_FILENAME)
        try:
            self.send_and_receive(msg)
        except Exception as ex:
            logger.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
            return
        
        error_pattern = re.compile("Exception|Error", re.IGNORECASE)
        error_matcher = error_pattern.search(msg.response.text)
        url_filename = urlparse(msg.url).path.split("/")[-1]
        
        if url_filename and (not self.is_page_200(msg) or error_matcher):
            logger.debug(f"It is possible to check for local file Path Traversal on the URL filename on [{msg.method}] [{msg.url}], [{param}]")
            
            for prefix in self.LOCAL_FILE_RELATIVE_PREFIXES:
                prefixed_url_filename = prefix + url_filename
                msg = self.get_new_msg(base_url, method)
                self.set_parameter(msg, param, prefixed_url_filename)
                
                try:
                    self.send_and_receive(msg)
                except Exception as ex:
                    logger.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
                    continue
                
                error_matcher = error_pattern.search(msg.response.text)
                if self.is_page_200(msg) and not error_matcher:
                    self.create_unmatched_alert(param, prefixed_url_filename, method)
                    return
    
    def send_and_check_payload(self, base_url, param, new_value, pattern, check, method):
        msg:Request = self.get_new_msg(base_url, method)
        self.set_parameter(msg, param, new_value)
        
        logger.debug(f"Checking parameter [{param}] for Path Traversal (local file) with value [{new_value}]")
        
        try:
            self.send_and_receive(msg)
        except Exception as ex:
            logger.debug(f"Caught {ex.__class__.__name__} {ex} when accessing: {msg.url}")
            return False
        
        match = pattern.search(msg.response.text)
        if self.is_page_200(msg) and match:
            logger.debug(f"Match found: {match.group()}")
            self.create_matched_alert(param, new_value, match.group(), check, method)
            return True
        return False
    
    def get_new_msg(self, base_url, method):
        return requests.Request(method, base_url)
    
    def send_and_receive(self, msg: Request):
        prepared = msg.prepare()
        with requests.Session() as session:
            response = session.send(prepared)
            msg.response = response
        return response
    
    def set_parameter(self, msg: Request, param, value):
        if msg.method.upper() == 'GET':
            url_parts = list(urlparse(msg.url))
            query = dict(parse_qs(url_parts[4]))
            query[param] = [value]
            url_parts[4] = urlencode(query, doseq=True)
            msg.url = urlunparse(url_parts)
        elif msg.method.upper() == 'POST':
            if msg.data is None:
                msg.data = {}
            elif isinstance(msg.data, str):
                msg.data = parse_qs(msg.data)
            else:
                msg.data = dict(msg.data)
            msg.data[param] = value
            msg.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        msg.prepare()

    def is_page_200(self, msg):
        return msg.response.status_code == 200
    
    def create_unmatched_alert(self, param, attack, method):
        alert = Alert(
            risk_category="High", 
            msg_ref="ascanrules.pathtraversal",
            param=param,
            attack=attack,
            method=method
        )
        logger.debug(f"Unmatched alert created: {alert}")
        self.ALERTS.append(str(alert))
    
    def create_matched_alert(self, param, attack, evidence, check, method):
        alert = Alert(
            risk_category="High", 
            msg_ref="ascanrules.pathtraversal", 
            param=param,
            attack=attack,
            evidence=evidence,
            method=method
        )
        logger.debug(f"Matched alert created: {alert}")
        self.ALERTS.append(str(alert))
