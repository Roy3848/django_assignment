from django.urls import path
from API import views as v
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,TokenVerifyView
)


urlpatterns = [
    path('createAC/',v.CreateAPI.as_view(),name='createAC'),
    # path('login/',v.LoginUser.as_view(),name='login'),
    path('login/',v.UserLogin.as_view(),name='login'),  
    path('profile/',v.UserProfile.as_view(),name='profile'),   
    # path('auth',v.tokenauth.as_view(),name="auth"),
    path('createAdmin',v.CreateSuperUser.as_view(),name='createAdmin'),
    path('createMG',v.CreateManager.as_view(),name='createManager'),
    path('logout',v.UserLogout.as_view(),name='logout'),
    path('cngPass/',v.ChangePassword.as_view(),name='ChangePass'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('forget/pass/',v.ForgotPassword.as_view(), name='Forget Pass'),
    path('forget/pass/link',v.ForgotPasswordUserRequest.as_view(),name="forgotpass"),
]
