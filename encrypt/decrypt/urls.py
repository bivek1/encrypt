from django.urls import path

from .import views
app_name = "decrypt"

urlpatterns = [
    path('', views.homepage, name= "homepage"),
    path('login', views.LoginF, name="login"),
    path('homepage', views.userHomepage, name="userhome"),
    path('signup', views.signUp, name="signup"),
    path('history', views.history, name = "history"),
    path('decryption/<int:id>', views.decrypt, name = "decrypt"),
    path('aes', views.aes, name="aes"),
    path('rsa', views.rsa, name = "rsa"),
    path('blowfish', views.blowfish, name="blowfish"),
    path('multiencryption', views.multiencryption_f , name="mutliencryption"),
    path('logout', views.Logout, name="logout")
]