import re

def is_malicious_regex_payload(input_str):
    patterns = [
        r"(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>",
        r"(?i)<\s*img[^>]*on\w+\s*=.*?>",
        r"(?i)<\s*iframe[^>]*>.*?<\s*/\s*iframe\s*>",
        r"(?i)<\s*(svg|math)[^>]*>.*?<\s*/\s*\1\s*>",
        r"(?i)<\s*style[^>]*>.*?expression\s*\(.*?\)",
        r"(?i)<\s*body[^>]*onload\s*=.*?>",
        r"(?i)javascript\s*:",
        r"(?i)vbscript\s*:",
        r"(?i)data\s*:[^,]*,.*",
        r"(?:\\x[a-fA-F0-9]{2})+",  
        r"(?:&#x?[0-9a-fA-F]+;)+",  
        r"(?i)on\w+\s*=",
        r"(?i)(union\s+select|select\s+.*from|insert\s+into|drop\s+table|or\s+1=1)",
        r"(?i)<[^>]+on\w+\s*=\s*['\"]?[^>]+['\"]?",
        r'<\s*(a|img|iframe|svg|object|embed|form)[^>]*>',
        r'(href|src|action)\s*=\s*["\']?(javascript:|data:|//|http|ftp)',
        r'<\s*(a|iframe|img|object|svg|form)[^>]*>',
        r'(href|src|action)\s*=\s*["\']?(javascript:|data:|//|ftp|http)',
        # STYLE tags with JS/CSS abuse
        r'<style[^>]*?>.*?(expression|javascript|vbscript|url\s*\(\s*["\']?\s*javascript)',

        # SCRIPT inside comments (IE conditional)
        r'<!--\[if.*?<script>.*?</script>.*?<!\[endif\]-->',  

        # Object/embed/scriptlet
        r'<(object|embed|scriptlet|xml|meta|base|iframe)[^>]*?>',

        # src/href/action with javascript/data URIs
        r'(src|href|action)\s*=\s*["\']?\s*(javascript|data):',

        # on* event handlers
        r'on\w+\s*=\s*["\']?.*?',

        # BASE href with JS scheme
        r'<base\s+href\s*=\s*["\']?\s*javascript:.*?>',

        # Charset trick (UTF-7)
        r'charset\s*=\s*[\'"]?utf-7',

        # IMG/CDATA/XML abuse
        r'<img[^>]+src\s*=\s*[\'"]?javascript:',
        r'<!\[CDATA\[.*?script:.*?\]\]>',
        r'<xml[^>]*?>.*?</xml>',
        r'datasrc\s*=\s*["\']?#\w+["\']?',  # binding HTML to XML
        r'datafld\s*=\s*["\']?\w+["\']?',
        r'dataformatas\s*=\s*["\']?html["\']?',

        # eval, alert, etc (used in obfuscated payloads)
        r'\b(alert|eval|prompt|document\.write|location)\s*\(',

        # Obfuscated/encoded tricks
        r'(?:\\x[0-9a-fA-F]{2})+',
        r'(?:%[0-9a-fA-F]{2}){2,}',  # double-encoding
        # Protocol-relative links (//...)
        r'href\s*=\s*["\']?\s*//',

        # href to suspicious domains/IP tricks
        r'href\s*=\s*["\']?(http|https|ftp|data|javascript|vbscript):',

        # href containing encoded trickery
        r'href\s*=\s*["\']?(%[0-9a-fA-F]{2}){2,}',
        r'<\s*a\s+[^>]*>'




    ]

    for pattern in patterns:
        if re.search(pattern, input_str):
            return True
    return False
