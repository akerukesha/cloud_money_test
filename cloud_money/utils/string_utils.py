import string

def empty_to_none(s):
    """
    """
    if s is not None:
        if len(s) == 0:
            return None
    return s