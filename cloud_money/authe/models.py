from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, PermissionsMixin

from utils import time_utils
from utils.constants import PASSWORD_TYPES, USER_PASSWORD, NO_PASSWORD, GENERATED_PASSWORD


class MainUserManager(BaseUserManager):
    """
    """
    def create_user(self, username, password=None, is_active=None):
        if not username:
            raise ValueError('Users must have an username')
        user = self.model(username=username)
        user.set_password(password)
        user.password_type = USER_PASSWORD
        user.timestamp = time_utils.get_timestamp_in_milli()
        if is_active is not None:
            user.is_active = is_active
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password):
        """
        """
        user = self.create_user(username, password=password)
        user.email = username
        user.is_admin = True
        user.is_superuser = True
        user.is_moderator = True
        user.save(using=self._db)
        return user


class MainUser(AbstractBaseUser, PermissionsMixin):
    """
    """
    username = models.CharField(max_length=100, blank=False, unique=True,
                                                    verbose_name=u'Username')
    full_name = models.CharField(max_length=555, blank=True,
                                                    verbose_name=u'Full name')
    email = models.CharField(max_length=50, blank=True,
                                                    verbose_name=u'E-mail')
    is_active = models.BooleanField(default=True, verbose_name=u"Active")
    is_admin = models.BooleanField(default=False, verbose_name=u'Admin')
    is_moderator = models.BooleanField(default=False, verbose_name=u"Moderator")
    password_type = models.SmallIntegerField(choices=PASSWORD_TYPES,
                    default=NO_PASSWORD, verbose_name=u"Password type")

    timestamp = models.BigIntegerField(default=0)

    objects = MainUserManager()
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    def __unicode__(self):
        return self.username

    def is_staff(self):
        """
        """
        return self.is_admin or self.is_moderator

    def get_full_name(self):
        return u"{} {}".format(self.username, self.full_name)

    def get_short_name(self):
        return self.username

    def full(self, with_favorites=False):
        obj = {
            'id': self.id,
            'username': self.username,
            'full_name': self.full_name,
            'timestamp': self.timestamp,
            'email': self.email,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'is_moderator': self.is_moderator,
            'password_type': self.password_type,
        }
        return obj

    def generate_new_password(self):
        new_password = password.generate_password(
                    length=settings.PASSWORD_LENGTH)

        self.set_password(new_password)
        self.password_type = GENERATED_PASSWORD
        self.save()
        return new_password

    class Meta:
        verbose_name = u"User"
        verbose_name_plural = u"Users"


class TokenLog(models.Model):
    """
    """
    token = models.CharField(max_length=500, blank=False, null=False)
    user = models.ForeignKey(MainUser, blank=False, null=False,
                                                        related_name='tokens')

    deleted = models.BooleanField(default=False)

    def __unicode__(self):
        return "token={0}".format(self.token)

    class Meta:
        index_together = [
            ["token", "user"]
        ]