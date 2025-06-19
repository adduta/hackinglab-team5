import re
def clean_ansi_escape_codes(text: str) -> str:
    """Remove ANSI escape codes from text"""
    if not text:
        return ""
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    return ansi_escape.sub('', text)