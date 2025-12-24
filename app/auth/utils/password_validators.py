import re
from djast.settings import settings
from auth.exceptions import PasswordIsWeak


def check_password_strength(password: str) -> bool:
    """ Checks if the given password meets the strength requirements.

    Args:
        password (str): The password string to check.

    Raises:
        PasswrodStrengthError: If the password does not meet strength requirements.

    Returns:
        bool: True if the password meets strength requirements.
    """
    pattern = re.compile(settings.PASSWORD_VALIDATION_REGEX)
    if not pattern.match(password):
        raise PasswordIsWeak("Password is too weak.")
    return True
