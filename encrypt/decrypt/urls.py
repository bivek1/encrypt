from django.urls import path

from .import views
app_name = "decrypt"

urlpatterns = [
    path('', views.homepage, name= "homepage"),
    path('login', views.LoginF, name="login"),
    path('homepage', views.userHomepage, name="userhome"),
    path('signup', views.signUp, name="signup"),
    path('history', views.history, name = "history"),
    path('encryption', views.encrypt, name = "encrypt"),
    path('decryption', views.decrypt, name = "decrypt"),
    path('logout', views.Logout, name="logout")
]