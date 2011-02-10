from __future__ import absolute_import

from django.contrib.auth.models import User
from django.db import models


class Token(models.Model):
    token_string = models.CharField(max_length=32)
    token_type = models.Integer(ChoiceField)

    user = models.ForeignKey(User, null=True, blank=True)

    creation_date = models.DateTimeField()
    expiry_date = models.DateTimeField(null=True, blank=True)
