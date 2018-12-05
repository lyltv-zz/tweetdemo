# import django.dispatch
#
# reset_password_token_created = django.dispatch.Signal(
#     providing_args=["reset_password_token"],
# )
#
# pre_password_reset = django.dispatch.Signal(providing_args=["user"])
#
# post_password_reset = django.dispatch.Signal(providing_args=["user"])
#
#
from django.shortcuts import redirect

from django.core.mail import send_mail


def send_token(user, token):
    EMAIL_HOST_USER = 'lyle@gmail.tamdongtam.vn'
    subject = 'Reset password'
    message = 'http://127.0.0.1:8000/accounts/reset/' + str(user.username) + '/' + token.generate_key() + '\n Username: ' + user.username
    email_from = EMAIL_HOST_USER
    recipient_list = [user.email,]
    print(message)
    send_mail(subject, message, email_from, recipient_list)

    return redirect('login')



