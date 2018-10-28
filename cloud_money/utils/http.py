# -*- coding: utf-8 -*-
from django.contrib.auth import get_user_model
from django.conf import settings
from django.http import HttpResponse
from functools import wraps
import codes
import token
import json
import messages
import string_utils

User = get_user_model()


def extract_token_from_request(request):
    """
    Extracts token string from request. First tries to get it from AUTH_TOKEN
    header, if not found (or empty) tries to get from cookie.
    :param request:
    :return: Token string found in header or cookie; null otherwise.
    """
    header_names_list = settings.AUTH_TOKEN_HEADER_NAME
    token_string = None
    for name in header_names_list:
        if name in request.META:
            token_string = string_utils.empty_to_none(request.META[name])

    if token_string is None:
        token_string = request.COOKIES.get(
                       settings.AUTH_TOKEN_COOKIE_NAME, None)

    if token_string is None:
        token_string = request.POST.get(
                settings.AUTH_TOKEN_POST_NAME, None)

    return string_utils.empty_to_none(token_string)


def extract_cookie_from_request(request):
    """
    Extracts user cookie string from request. Tries get it from cookie.
    :param request:
    :return: user_cookie string found in cookie; null otherwise.
    """
    user_cookie_string = request.COOKIES.get(settings.USER_COOKIE_NAME, None)

    return string_utils.empty_to_none(user_cookie_string)


def required_parameters(parameters_list):
    """
    Decorator to make a view only accept request with required parameters.
    :param parameters_list: list of required parameters.
    """
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if request.method == "POST":
                for parameter in parameters_list:
                    value = (
                        string_utils.empty_to_none(request.POST.get(parameter)
                            or request.FILES.get(parameter)))
                    if value is None:
                        return code_response(
                                codes.MISSING_REQUIRED_PARAMS,
                                message=messages.MISSING_REQUIRED_PARAMS.format(parameter))
            else:
                for parameter in parameters_list:
                    value = string_utils.empty_to_none(
                        request.GET.get(parameter))
                    if value is None:
                        return code_response(
                                codes.MISSING_REQUIRED_PARAMS,
                                message=messages.MISSING_REQUIRED_PARAMS.format(parameter))

            return func(request, *args, **kwargs)
        return inner
    return decorator


def require_http_methods(param):
    """
    Decorator to make a view only accept request with required http method.
    :param required http method.
    """
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            if request.method != param:
                return code_response(codes.INCORRECT_HTTP_METHOD, message=param)
            return func(request, *args, **kwargs)
        return inner
    return decorator


def moderators_token():
    """
    Decorator to make a view only accept request with valid token.
    """
    def decorator(func):
        @wraps(func)
        def inner(request, user, *args, **kwargs):
            if not user.is_moderator:
                return code_response(codes.PERMISSION_DENIED)
            return func(request, user, *args, **kwargs)
        return inner
    return decorator


def requires_token():
    """
    Decorator to make a view only accept request with valid token.
    """
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            
            token_string = extract_token_from_request(request)
            if token_string is None:
                return code_response(codes.BAD_REQUEST)

            user = token.verify_token(token_string)
            if user is None:
                return code_response(codes.TOKEN_INVALID)

            return func(request, user, *args, **kwargs)
        return inner
    return decorator


def requires_token_with_extraction():
    """
    Decorator to make a view only accept request with valid token and extracting token_string.
    """
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            token_string = extract_token_from_request(request)
            if token_string is None:
                return code_response(codes.BAD_REQUEST, message=messages.TOKEN_NOT_FOUND)

            user = token.verify_token(token_string)
            if user is None:
                return code_response(codes.TOKEN_INVALID, message=messages.TOKEN_INVALID)

            return func(request, user, token_string, *args, **kwargs)
        return inner
    return decorator


def requires_cookie_or_token():
    """
    Decorator to make a view only accept request with valid token or cookie.
    """
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            token_string = extract_token_from_request(request)
            cookie_string = extract_cookie_from_request(request)

            if token_string is None and cookie_string is None:
                return code_response(codes.BAD_REQUEST, message=messages.MISSING_REQUIRED_PARAMS.format("token or cookie"))

            user = None
            if token_string:
                user = token.verify_token(token_string)

            return func(request, user, cookie_string, *args, **kwargs)
        return inner
    return decorator


def extract_token_or_cookie_from_request():
    """
    Decorator to extract token or cookie or both of them
    """
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            token_string = extract_token_from_request(request)
            cookie_string = extract_cookie_from_request(request)

            user = None
            if token_string:
                user = token.verify_token(token_string)

            return func(request, user, cookie_string, *args, **kwargs)
        return inner
    return decorator


def http_response_with_json_body(body):
    return HttpResponse(body, content_type="application/json")


def http_response_with_json(json_object):
    return http_response_with_json_body(json.dumps(json_object))


def json_response():
    """
    Decorator that wraps response into json.
    """
    def decorator(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            response = func(request, *args, **kwargs)
            if not ('code' in response):
                response['code'] = codes.OK
            response = http_response_with_json(response)
            if settings.USER_COOKIE_NAME not in request.COOKIES:
                response.set_cookie(settings.USER_COOKIE_NAME, token.generate_cookie())
            return response
        return inner
    return decorator


def code_response(code, message=None, errors=None):
    result = {'code': code}
    if message:
        result['message'] = message
    if errors:
        result['errors'] = errors
    return result


def ok_response():
    return code_response(codes.OK)