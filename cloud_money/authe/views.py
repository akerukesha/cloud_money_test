from django.shortcuts import render

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.validators import validate_email

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from utils import codes, messages, token, http, time_utils
from utils.constants import USER_PASSWORD


User = get_user_model()


def index(request):
    return HttpResponse("Authe index.")


@csrf_exempt
@http.json_response()
@http.require_http_methods("POST")
@http.required_parameters(["email", "password"])
def register(request):
    """
    """
    try:
        email = request.POST.get('email', '').lower()
        try:
            validate_email(email)
        except Exception as e:
            return http.code_response(code=codes.BAD_EMAIL,
                                      message=messages.BAD_EMAIL.format(email))

        _password = request.POST.get('password', '')
        if len(_password) < settings.PASSWORD_LENGTH:
            return http.code_response(
                code=codes.PASSWORD_LENGTH_ERROR,
                message=messages.PASSWORD_LENGTH_ERROR.format(len(_password)))
        
        if User.objects.filter(email__iexact=email, is_active=True).exists():
            return http.code_response(code=codes.USERNAME_USED,
                                      message=messages.USERNAME_USED)

        new_user, _ = User.objects.get_or_create(username=email)
        new_user.set_password(_password)
        new_user.password_type = USER_PASSWORD
        new_user.full_name = request.POST.get("full_name", "")
        new_user.email = email
        new_user.save()
        return {
            'user': new_user.full()
        }
    except Exception as e:
        return http.code_response(codes.SERVER_ERROR, message=str(e))


@csrf_exempt
@http.json_response()
@http.require_http_methods("POST")
@http.required_parameters(["username", "password"])
def login(request):
    """
    """
    try:
        username = request.POST.get("username").lower()
        password = request.POST.get("password")
        user = None
        try:
            validate_email(username)
            user = User.objects.filter(email=username).first()
        except:
            return http.code_response(code=codes.INVALID_USERNAME,
                                          message=messages.INVALID_USERNAME)
        if user is None:
            return http.code_response(code=codes.USERNAME_NOT_FOUND,
                                      message=messages.USER_NOT_FOUND)

        user = authenticate(username=user.username, password=password)

        if user is None:
            return http.code_response(
                code=codes.INCORRECT_USERNAME_OR_PASSWORD,
                message=messages.INCORRECT_USERNAME_OR_PASSWORD)

        user.timestamp = time_utils.get_timestamp_in_milli()
        user.save()
        return {
            'token': token.create_token(user),
            'user': user.full()
        }
    except Exception as e:
        return http.code_response(codes.SERVER_ERROR, message=str(e))


@csrf_exempt
@http.json_response()
@http.require_http_methods("POST")
@http.requires_token_with_extraction()
def logout(request, user, token_string):
    """
    """
    try:
        if token.delete_token(token_string):
            return http.ok_response()
        else:
            return http.code_response(code=codes.TOKEN_INVALID,
                                      message=messages.TOKEN_INVALID)
    except Exception as e:
        return http.code_response(codes.SERVER_ERROR, message=str(e))