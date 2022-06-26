from django.urls import path
from API import views as v


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
]
