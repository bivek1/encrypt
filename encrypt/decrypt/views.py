from urllib import request
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .models import History, FileList
# Create your views here.
def homepage(request):
    return render(request, "index.html")

def LoginF(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username = username, password = password)
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(reverse('decrypt:userhome'))
        else:
            messages.error(request,"Wrong Username and Password")
            return HttpResponseRedirect(reverse('decrypt:login'))
    else:
        return render(request, "login.html")

def userHomepage(request):
    fil = FileList.objects.filter(user = request.user)
    if request.method == 'POST':
        file = request.FILES['userFile']
        FileList.objects.create(name="new", file = file, user = request.user)
        messages.success(request,"Successfully Added File")
        return HttpResponseRedirect(reverse('decrypt:userhome'))
    dist ={
        'filelist':fil
    }
    return render(request, "homepage.html", dist)


def signUp(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['password2']
        # Validating Password one and password two
        if password != password2:
            messages.error(request,"Wrong Username and Password")
            return HttpResponseRedirect(reverse('decrypt:signup'))
        else:
            try:
                user = User.objects.create_user(username, username+"@data.com", password)
                user.save()
                user1 = authenticate(username = username, password = password)
                if user1 is not None:
                    login(request, user1)
                    return HttpResponseRedirect(reverse('decrypt:userhome'))
            except:
                messages.error(request,"Somethig Went Wrong")
                return HttpResponseRedirect(reverse('decrypt:signup'))
    else:
        return render(request, "signup.html")
        

def Logout(request):
    logout(request)
    return HttpResponseRedirect(reverse('decrypt:login'))