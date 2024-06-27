import logging
from src.active_scan.active_scan_rules.path_transversal_scan_rule import PathTraversalScanRule

def main():
    logging.basicConfig(level=logging.DEBUG)
    url = "https://testportal.helium.sh/mod.php"
    param = "kategori"

    scan_rule = PathTraversalScanRule()
    print(str(scan_rule.scan(url, param, method="POST")))


if __name__ == "__main__":
    main()