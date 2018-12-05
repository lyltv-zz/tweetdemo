# from datetime import timedelta

from django.contrib.auth import get_user_model, views
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404, redirect
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView
from django.views.generic.edit import FormView
from django.core.exceptions import ValidationError
from django.urls import reverse, reverse_lazy

from rest_framework import parsers, renderers, status
from rest_framework.views import APIView
from rest_framework.response import Response
# Create your views here.
from rest_framework import permissions, status

from .models import UserProfile, ResetPasswordToken, EmailSerializer, ResetPasswordValidator, PasswordTokenSerializer #, ResetPasswordValidator, check_expired_time_reset_token
from .forms import UserRegisterForm
from .signals import send_token #, pre_password_reset, post_password_reset
User = get_user_model()


class UserRegisterView(FormView):
    form_class = UserRegisterForm
    template_name = 'accounts/user_register_form.html'
    success_url = '/login'

    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password')
        new_user = User.objects.create(username=username, email=email)
        new_user.set_password(password)
        new_user.save()
        return super(UserRegisterView, self).form_valid(form)


class UserDetailView(DetailView):
    template_name = 'accounts/user_detail.html'
    queryset = User.objects.all()
    
    def get_object(self):
        return get_object_or_404(
                    User, 
                    username__iexact=self.kwargs.get("username")
                    )

    def get_context_data(self, *args, **kwargs):
        context = super(UserDetailView, self).get_context_data(*args, **kwargs)
        following = UserProfile.objects.is_following(self.request.user, self.get_object())
        context['following'] = following
        return context


class UserFollowView(View):
    def get(self, request, username, *args, **kwargs):
        toggle_user = get_object_or_404(User, username__iexact=username)
        if request.user.is_authenticated():
            is_following = UserProfile.objects.toggle_follow(request.user, toggle_user)
        return redirect("profiles:detail", username=username)
        # url = reverse("profiles:detail", kwargs={"username": username})
        # HttpResponseRedirect(url)


# def get_password_reset_token_expiry_time():
#     """
#     Returns the password reset token expirty time in hours (default: 24)
#     Set Django SETTINGS.DJANGO_REST_MULTITOKENAUTH_RESET_TOKEN_EXPIRY_TIME to overwrite this time
#     :return: expiry time
#     """
#     # get token validation time
#     return getattr(settings, 'DJANGO_REST_MULTITOKENAUTH_RESET_TOKEN_EXPIRY_TIME', 24)
#

class ResetPasswordRequestToken(APIView):
    """
    An Api View which provides a method to request a password reset token based on an e-mail address
    Sends a signal reset_password_token_created when a reset token was created
    """

    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = EmailSerializer
    # get_success_url = reverse_lazy('password_reset/done')

    def post(self, request, *args, **kwargs):
        print('==========25')
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        # before we continue, delete all existing expired tokens
        # password_reset_token_validation_time = get_password_reset_token_expiry_time()
        password_reset_token_validation_time = timezone.now()
        # datetime.now minus expiry hours
        now_minus_expiry_time = timezone.now()

        # delete all tokens where created_at < now - 24 hours
        ResetPasswordToken.objects.filter(created_at__lte=now_minus_expiry_time).delete()

        # find a user by email address (case insensitive search)
        users = User.objects.filter(email__iexact=email)

        active_user_found = False

        # iterate over all users and check if there is any user that is active
        # also check whether the password can be changed (is useable), as there could be users that are not allowed
        # to change their password (e.g., LDAP user)
        for user in users:
            if user.is_active:
                active_user_found = True

        # No active user found, raise a validation error
        if not active_user_found:
            raise ValidationError({
                'email': ValidationError("No user matched to this email", code='invalid')}
            )

        # last but not least: iterate over all users that are active and can change their password
        # and create a Reset Password Token and send a signal with the created token
        for user in users:
            if user.is_active:
                # define the token as none for now
                token = None

                # check if the user already has a token
                if user.password_reset_tokens.all().count() > 0:
                    # yes, already has a token, re-use this token
                    token = user.password_reset_tokens.all()[0]
                else:
                    # no token exists, generate a new token
                    token = ResetPasswordToken.objects.create(
                        user=user,
                        user_agent=request.META['HTTP_USER_AGENT'],
                        ip_address=request.META['REMOTE_ADDR']
                    )
                # send a signal that the password token was created
                # let whoever receives this signal handle sending the email for the password reset
                send_token(user, token)
        # done
        return redirect(reverse_lazy('password_reset_done'))


class ResetPassword(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        validator = ResetPasswordValidator(data=request.data)
        if not validator.is_valid():
            return Response(validator.errors, status=status.HTTP_400_BAD_REQUEST)
        reset_token = validator.validated_data['reset_token']
        print(reset_token)
        password = validator.validated_data['password']
        try:
            reset_token = ResetPasswordToken.objects.get(reset_token=reset_token)
        except Exception:
            return Response('Not found reset token', status=status.HTTP_404_NOT_FOUND)

        user = reset_token.user
        # if not user_utils.check_expired_time_reset_token(reset_token):
        #     reset_token.delete()
        #     return Response('Token has expired', status=status.HTTP_404_NOT_FOUND)

        user.set_password(password)
        user.save()

        reset_token.delete()
        # device_id = core_utils.get_device_id_from_request(request)
        # device_type = core_utils.get_device_type_from_request(request)
        # user.user_type = user_utils.get_user_type(user_id=user.id, device_id=device_id, device_type=device_type)
        # serializer = UserSerializer(user)
        return redirect(reverse_lazy('login'))
    #
    # def get(self, request, token):
    #     # validator = ResetPasswordValidator(reset_token=token)
    #     # reset_token = validator.validated_data['reset_token']
    #     # try:
    #     #     reset_token = ResetPasswordToken.objects.get(reset_token=reset_token)
    #     # except Exception:
    #     #     return Response('Url invalid', status=status.HTTP_404_NOT_FOUND)
    #
    #     return render(request, 'registration/password_reset_confirm.html')

