import string


def get_key_from_username(email_username: str) -> bytes:
    prefix = "message-"
    allowed_characters = string.ascii_letters + string.digits + ".-"
    return (prefix + "".join(char for char in email_username if char in allowed_characters)).encode("ascii")
