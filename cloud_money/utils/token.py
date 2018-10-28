from authe.models import TokenLog
from django.conf import settings
from django.contrib.auth import get_user_model
import jwt
import time
import random
import string
import time_utils

User = get_user_model()


def create_token(user):
    """
    Creates token string.
    :param user: User for which token should be created.
    :return: authentication token.
    """
    print user
    info = {
        'id': user.id,
        'username': user.username,
        'timestamp': time_utils.get_timestamp_in_milli()
    }
    token = jwt.encode(info, settings.JWT_KEY, settings.JWT_ALGORITHM)
    TokenLog.objects.create(user=user, token=token)
    return token


def verify_token(token_string):
    """
    Verifies token string.
    :param token_string: Token string to verify.
    :return: Profile/user object if token is valid; None is token is invalid.
    """
    try:
        result = jwt.decode(
            token_string, settings.JWT_KEY, settings.JWT_ALGORITHM)
        user_id = result['id']
        username = result['username']
        user = User.objects.get(id=user_id)
        # Check if token exists in TokenLog and not deleted
        user.tokens.get(token=token_string, deleted=False)

        if (user.username != username
           and user.email != username):
            return None

        return user
    except Exception, e:
        print e
        return None


def delete_token(token_string):
    """
    Deletes token string.
    :param token_string: Token string to delete.
    :return: True if token is valid and removed succesfully; False if token is invalid.
    """
    try:
        result = jwt.decode(
            token_string, settings.JWT_KEY, settings.JWT_ALGORITHM)
        user_id = result['id']
        username = result['username']
        user = User.objects.get(id=user_id)
        token_log = user.tokens.get(token=token_string, deleted=False)

        if user.username != username:
            return False

        token_log.deleted = True
        token_log.save()
        return True
    except Exception, e:
        print e
        return False


def get_deep_link_token(token):
    """
    Creates token string.
    :param user: User for which token should be created.
    :return: authentication token.
    """
    info = {
        'token': token
    }
    new_token = jwt.encode(
        info, settings.JWT_DEEP_LINK_KEY, settings.JWT_ALGORITHM)
    
    return new_token


def generate_cookie():
    """
    Generates cookie string
    :return: cookie string.
    """
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits)
        for _ in xrange(settings.COOKIE_LENGTH))