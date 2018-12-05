from django.conf.urls import url, include
from django.contrib.auth import views as auth_views

from django.views.generic.base import RedirectView

from .views import (
    UserDetailView,
    UserFollowView,
    ResetPasswordRequestToken,
    ResetPassword
    )


app_name = "accounts"
urlpatterns = [
    # url(r'^search/$', TweetListView.as_view(), name='list'), # /tweet/
    # url(r'^create/$', TweetCreateView.as_view(), name='create'), # /tweet/create/
    url(r'^password_reset/', ResetPasswordRequestToken.as_view(), name='password_reset'),
    # url(r'^password_reset/done/$', auth_views.password_reset_done, name='password_reset_done'),
    # url(r'^reset/(?P<token>[a-zA-Z0-9]+)/$',
    #     ResetPassword.as_view()),

    url(r'^reset/', auth_views.password_reset_confirm, name='password_reset_confirm'),
    url(r'^(?P<username>[\w.@+-]+)/$', UserDetailView.as_view(), name='detail'), # /tweet/1/
    url(r'^(?P<username>[\w.@+-]+)/follow/$', UserFollowView.as_view(), name='follow'),
    # url(r'^(?P<pk>\d+)/update/$', TweetUpdateView.as_view(), name='update'), # /tweet/1/update/
    # url(r'^(?P<pk>\d+)/delete/$', TweetDeleteView.as_view(), name='delete'), # /tweet/1/delete/
]

