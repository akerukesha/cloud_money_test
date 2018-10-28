from django.contrib import admin

from models import MainUser, TokenLog

admin.site.register(MainUser)
admin.site.register(TokenLog)