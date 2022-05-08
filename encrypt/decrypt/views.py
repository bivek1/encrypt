from hashlib import new
from re import T
from urllib import request, response
from django.urls import reverse
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .models import History, FileList
from .aes import EncryptNow, DecryptNow
from django.conf import settings
# Import mimetypes module

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
    fil = FileList.objects.filter(user = request.user).filter(decrypted= False)
    if request.method == 'POST':
        file = request.FILES['userFile']
        name = request.POST['nameFile']
        password = request.POST['password']

        # Adding File or object to database
        obj = FileList.objects.create(name=name, file = file, user = request.user)
        History.objects.create(file = obj)
        print(obj.file.url)
        raw_path = str(settings.MEDIA_ROOT)
        print(raw_path)
        path = raw_path+"\\encrypt\\"+str(file)
        EncryptNow(path, password)
        obj.file = path+".enc"
        obj.save()
        # os.remove(path)

        messages.success(request,"Successfully Added File")
        return HttpResponseRedirect(reverse('decrypt:userhome'))
    dist ={
        'filelist':fil
    }
    return render(request, "homepage.html", dist)


def decrypt(request, id):
    file = FileList.objects.get(id = id)

    dist = {
        'file':file
    }

    if request.method == 'POST':
        password = request.POST['password']
        print(password)
        print(file.file.url)
        DecryptNow(str(file.file), password)
        path = str(file.file)[:-4]
        file.file = path
        file.decrypted = True
        file.save()
        return HttpResponseRedirect(reverse('decrypt:decrypt', args=[file.id]))
        # except:
        #     messages.success(request, "Your password Didn't match")
        #     return HttpResponseRedirect(reverse('decrypt:decrypt', args=[file.id]))
    return render(request, "decrypt.html", dist)

    

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


def history(request):
    history = History.objects.filter(file__user =request.user)
    dist = {
        'history':history,
    }

    return render(request, "history.html", dist)