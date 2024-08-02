import re

# Define the corrected hash patterns dictionary
hash_patterns = {
    re.compile(r"\$LM\$[a-f0-9]{16}", re.IGNORECASE): ("LanMan / DES", "High", "High"),
    re.compile(r"\$K4\$[a-f0-9]{16}", re.IGNORECASE): ("Kerberos AFS DES", "High", "High"),
    re.compile(r"\$2a\$05\$[a-z0-9\+\-_./=]{53}", re.IGNORECASE): ("OpenBSD Blowfish", "High", "High"),
    re.compile(r"\$2y\$05\$[a-z0-9\+\-_./=]{53}", re.IGNORECASE): ("OpenBSD Blowfish", "High", "High"),
    re.compile(r"\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{1,22}"): ("MD5 Crypt", "High", "High"),
    re.compile(r"\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}"): ("SHA-256 Crypt", "High", "High"),
    re.compile(r"\$5\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}"): ("SHA-256 Crypt", "High", "High"),
    re.compile(r"\$6\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}"): ("SHA-512 Crypt", "High", "High"),
    re.compile(r"\$6\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}"): ("SHA-512 Crypt", "High", "High"),
    re.compile(r"\$2\$[0-9]{2}\$[./0-9A-Za-z]{53}"): ("BCrypt", "High", "High"),
    re.compile(r"\$2a\$[0-9]{2}\$[./0-9A-Za-z]{53}"): ("BCrypt", "High", "High"),
    re.compile(r"\$3\$\$[0-9a-f]{32}"): ("NTLM", "High", "High"),
    re.compile(r"\$NT\$[0-9a-f]{32}"): ("NTLM", "High", "High"),
    re.compile(r"\b[0-9A-F]{48}\b"): ("Mac OSX salted SHA-1", "High", "Medium"),
    re.compile(r"\b[0-9a-f]{128}\b", re.IGNORECASE): ("SHA-512", "Low", "Low"),
    re.compile(r"\b[0-9a-f]{96}\b", re.IGNORECASE): ("SHA-384", "Low", "Low"),
    re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE): ("SHA-256", "Low", "Low"),
    re.compile(r"\b[0-9a-f]{56}\b", re.IGNORECASE): ("SHA-224", "Low", "Low"),
    re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE): ("SHA-1", "Low", "Low"),
    re.compile(r"(?<!jsessionid=)\b[0-9a-f]{32}\b", re.IGNORECASE): ("MD4 / MD5", "Low", "Low"),
}

# List of known hashes and their expected types
# Traditional DES: causes *way* too many false positives to enable this
test_hashes = [
    ("$LM$1234567890abcdef", "LanMan / DES"),
    ("$K4$1234567890abcdef", "Kerberos AFS DES"),
    ("$2a$05$abcdefghijklmnopqrstuvwx/yz1234567890abcdefghi=", "OpenBSD Blowfish"),
    ("$2y$05$abcdefghijklmnopqrstuvwx/yz1234567890abcdefghi=", "OpenBSD Blowfish"),
    ("$1$salt$abcdefghijklmno", "MD5 Crypt"),
    ("$5$MnfsQ4iN$ZMTppKN16y/tIsUYs/obHlhdP.Os80yXhTurpBMUbA5", "SHA-256 Crypt"),
    ("$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6", "SHA-256 Crypt"),
    ("$6$salt$abcdefghijklmnopqrstuvwxyz1234567890123456789012345678901234567890", "SHA-512 Crypt"),
    ("$6$rounds=5000$salt$abcdefghijklmnopqrstuvwxyz1234567890123456789012345678901234567890", "SHA-512 Crypt"),
    ("$2a$12$abcdefghijklmnopqrstuvwx/yz1234567890abcdefghi=", "BCrypt"),
    ("$3$$1234567890abcdef1234567890abcdef", "NTLM"),
    ("$NT$1234567890abcdef1234567890abcdef", "NTLM"),
    ("1234567890abcdef1234567890abcdef1234567890abcdef", "Mac OSX salted SHA-1"),
    ("a" * 128, "SHA-512"),
    ("b" * 96, "SHA-384"),
    ("c" * 64, "SHA-256"),
    ("d" * 56, "SHA-224"),
    ("e" * 40, "SHA-1"),
    ("f" * 32, "MD4 / MD5"),
]

# Function to test hash patterns
def test_hash_patterns(hash_patterns, test_hashes):
    results = []
    for test_hash, expected_type in test_hashes:
        matched = False
        for pattern, (hash_type, severity, likelihood) in hash_patterns.items():
            if pattern.match(test_hash):
                results.append((test_hash, expected_type, hash_type, hash_type == expected_type))
                matched = True
                break
        if not matched:
            results.append((test_hash, expected_type, None, False))
    return results

# Run the test
results = test_hash_patterns(hash_patterns, test_hashes)

# Print the results
for test_hash, expected_type, detected_type, is_correct in results:
    print(f"Hash: {test_hash}\nExpected: {expected_type}\nDetected: {detected_type}\nCorrect: {is_correct}\n")

