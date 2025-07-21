
import html
import urllib.parse
import base64
import binascii
import re
from regexScanner import is_malicious_regex_payload

def decode_input(input_str):
    try:
        input_str = html.unescape(input_str)
        input_str = urllib.parse.unquote_plus(input_str)
        
        try:
            base64_decoded = base64.b64decode(input_str).decode('utf-8')
            if len(base64_decoded) > 5:  
                input_str += f" | Base64Decoded: {base64_decoded}"
        except Exception:
            pass

        hex_match = re.fullmatch(r'(?:\\x[a-fA-F0-9]{2})+', input_str)
        if hex_match:
            hex_decoded = bytes.fromhex(input_str.replace("\\x", "")).decode('utf-8', errors='ignore')
            input_str += f" | HexDecoded: {hex_decoded}"

        return input_str
    except Exception as e:
        return input_str  

def normalize_input_dict(input_data: dict) -> dict:
    normalized = {}
    for key, val in input_data.items():
        if isinstance(val, str):
            decoded_val = decode_input(val)
            is_malicious = is_malicious_regex_payload(decoded_val) 
            
            normalized[key] = {
                "raw": val,
                "decoded": decoded_val,
                "malicious": is_malicious
            }
        elif isinstance(val, list):
            normalized[key] = [{
                "raw": v,
                "decoded": decode_input(v),
                "malicious": is_malicious_regex_payload(decode_input(v))
            } for v in val]
    return normalized


if __name__ == "__main__":
    sample = {
    "q": "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "data": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",  
    "cmd": "\\x3Cscript\\x3Eevil()\\x3C/script\\x3E"
}
    print(normalize_input_dict(sample))