import binascii, os

from django.conf import settings
from django.db import models
from django.db.models.signals import post_save
from django.urls import reverse_lazy
from django.utils.translation import gettext_lazy as _


# Create your models here.
from rest_framework import serializers


class UserProfileManager(models.Manager):
    use_for_related_fields = True

    def all(self):
        qs = self.get_queryset().all()
        try:
            if self.instance:
                qs = qs.exclude(user=self.instance)
        except:
            pass
        return qs

    def toggle_follow(self, user, to_toggle_user):
        user_profile, created = UserProfile.objects.get_or_create(user=user) # (user_obj, true)
        if to_toggle_user in user_profile.following.all():
            user_profile.following.remove(to_toggle_user)
            added = False
        else:
            user_profile.following.add(to_toggle_user)
            added = True
        return added

    def is_following(self, user, followed_by_user):
        user_profile, created = UserProfile.objects.get_or_create(user=user)
        if created:
            return False
        if followed_by_user in user_profile.following.all():
            return True
        return False


class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, related_name='profile')  # user.profile
    following = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True, related_name='followed_by')
    # user.profile.following -- users i follow
    # user.followed_by -- users that follow me -- reverse relationship

    objects = UserProfileManager() # UserProfile.objects.all()
    # abc = UserProfileManager() # UserProfile.abc.all()

    def __str__(self):
        return str(self.following.all().count())

    def get_following(self):
        users  = self.following.all() # User.objects.all().exclude(username=self.user.username)
        return users.exclude(username=self.user.username)

    def get_follow_url(self):
        return reverse_lazy("profiles:follow", kwargs={"username":self.user.username})

    def get_absolute_url(self):
        return reverse_lazy("profiles:detail", kwargs={"username":self.user.username})

# cfe = User.objects.first()
# User.objects.get_or_create() # (user_obj, true/false)
# cfe.save()


AUTH_USER_MODEL = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')


class ResetPasswordToken(models.Model):
    class Meta:
        verbose_name = _("Password Reset Token")
        verbose_name_plural = _("Password Reset Tokens")

    @staticmethod
    def generate_key():
        """ generates a pseudo random code using os.urandom and binascii.hexlify """
        return binascii.hexlify(os.urandom(32)).decode()

    id = models.AutoField(
        primary_key=True
    )

    user = models.ForeignKey(
        AUTH_USER_MODEL,
        related_name='password_reset_tokens',
        on_delete=models.CASCADE,
        verbose_name=_("The User which is associated to this password reset token")
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("When was this token generated")
    )

    # Key field, though it is not the primary key of the model
    key = models.CharField(
        _("Key"),
        max_length=64,
        db_index=True,
        unique=True
    )

    ip_address = models.GenericIPAddressField(
        _("The IP address of this session"),
        default="127.0.0.1"
    )
    user_agent = models.CharField(
        max_length=256,
        verbose_name=_("HTTP User Agent"),
        default=""
    )

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(ResetPasswordToken, self).save(*args, **kwargs)

    def __str__(self):
        return "Password reset token for user {user}".format(user=self.user)


class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordTokenSerializer(serializers.Serializer):
    password = serializers.CharField(label=_("Password"), style={'input_type': 'password'})
    token = serializers.CharField()


class ResetPasswordValidator(serializers.Serializer):
    reset_token = serializers.CharField(required=True, allow_blank=False)
    password = serializers.CharField(required=False, allow_blank=False, min_length=6, max_length=16, )
    confirm_password = serializers.CharField(required=False, allow_blank=False)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Confirm password must equal password.")
        if not any(char.isalpha() for char in data['password']):
            raise serializers.ValidationError("Password must contain at least 1 letter.")
        return data


def post_save_user_receiver(sender, instance, created, *args, **kwargs):
    if created:
        new_profile = UserProfile.objects.get_or_create(user=instance)
        # celery + redis
        # deferred task


post_save.connect(post_save_user_receiver, sender=settings.AUTH_USER_MODEL)






