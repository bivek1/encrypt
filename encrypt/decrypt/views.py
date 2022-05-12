
import os
from django.urls import reverse
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import render
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.contrib.auth.models import User
from .models import History, FileList
from .aes import EncryptNow, DecryptNow
from .rsa import RSAEncryption
from .blowfish import BlowfishCipher
from django.conf import settings
from .multiencryption import HybridAESRSACipher
# Import mimetypes module


media_path = "G:/Client Work/Assignment Project/WebApp/encrypt/media/"
public_key = "G:\Client Work\Assignment Project\WebApp\public_key.pem"
private_key = "G:\Client Work\Assignment Project\WebApp\private_key.pem"


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
   
    dist ={
        'filelist':fil
    }
    return render(request, "homepage.html", dist)


def decrypt(request, id):
    file = FileList.objects.get(id = id)

    dist = {
        'file':file
    }
    file_path = str(file.file)
            
    path = file_path
    if request.method == 'POST':
        password = request.POST['password']
        action = request.POST['action']
        if action == "aes":
            DecryptNow(path, password)
            path = path[:-4]
            file.file = path
            file.decrypted = True
            file.save()

        elif action == "rsa":
            obj_e = RSAEncryption(public_key_loc=public_key, private_key_loc=private_key,
                            public_key_passphrase=password, private_key_passphrase=password)

            # file_path = "G:/Client Work/Assignment Project/WebApp\encrypt/media\encrypt/1.jpg"
            obj_e.decrypt_file(path)
            os.remove(path)
            path = path[:-4]
            file.file = path
            file.decrypted = True
            file.save()
        elif action == "blow":
            op = BlowfishCipher(password,'salt')
            op.decrypt_file(path)
            os.remove(path)
            path = path[:-4]
            file.file = path
            file.decrypted = True
            file.save()
        else: 
            obj_e = HybridAESRSACipher(public_key_loc=public_key, private_key_loc=private_key,
                            public_key_passphrase=password, private_key_passphrase=password)

            # file_path = "G:/Client Work/Assignment Project/WebApp\encrypt/media\encrypt/1.jpg"
            obj_e.decrypt_file(path)
            os.remove(path)
            path = path[:-4]
            file.file = path
            file.decrypted = True
            file.save()

        return HttpResponseRedirect(reverse('decrypt:decrypt', args=[file.id]))

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


# For RSA Encryption
def rsa(request):
    if request.method == "POST":
        file = request.FILES['userFile']
        name = request.POST['nameFile']
        password = request.POST['password']

        # Adding File or object to database
        obj = FileList.objects.create(name=name, file = file, user = request.user)
        History.objects.create(file = obj)
        print(obj.file)
        file_path = str(obj.file)

        
        path = media_path + file_path
       
        obj_e = RSAEncryption(public_key_loc=public_key, private_key_loc=private_key,
                        public_key_passphrase=password, private_key_passphrase=password)

        # file_path = "G:/Client Work/Assignment Project/WebApp\encrypt/media\encrypt/1.jpg"
        obj_e.encrypt_file(path)
        os.remove(path)
        obj.file = path+".enc"
        obj.save()
    
        messages.success(request,"Successfully Encrypted and Added File")
        return HttpResponseRedirect(reverse('decrypt:userhome'))
      
    return render(request, "rsa.html")



# For AES Encryption
def aes(request):

    if request.method == 'POST':
        file = request.FILES['userFile']
        name = request.POST['nameFile']
        password = request.POST['password']

        # Adding File or object to database
        obj = FileList.objects.create(name=name, file = file, user = request.user)
        History.objects.create(file = obj)
        file_path = str(obj.file)
        path = media_path + file_path
        EncryptNow(path, password)
        obj.file = path+".enc"
        obj.save()
        # os.remove(path)

        messages.success(request,"Successfully Encrypted and Added File")
        return HttpResponseRedirect(reverse('decrypt:userhome'))

    return render(request, "aes.html")


# Using BlowFish Method 

def blowfish(request):
    if request.method == 'POST':
        if request.method == 'POST':
            file = request.FILES['userFile']
            name = request.POST['nameFile']
            password = request.POST['password']

            # Adding File or object to database
            obj = FileList.objects.create(name=name, file = file, user = request.user)
            History.objects.create(file = obj)
            print(obj.file)
            file_path = str(obj.file)

            
            path = media_path + file_path
            op = BlowfishCipher(password,'salt')
            print(path)
            op.encrypt_file(path)
            os.remove(path)
            obj.file = path+".enc"
            obj.save()

            messages.success(request,"Successfully Encrypted and Added File")
        return HttpResponseRedirect(reverse('decrypt:userhome'))
      
    return render(request, "blowfish.html")


def multiencryption_f(request):
    if request.method == "POST":
        file = request.FILES['userFile']
        name = request.POST['nameFile']
        password = request.POST['password']

        # Adding File or object to database
        obj = FileList.objects.create(name=name, file = file, user = request.user)
        History.objects.create(file = obj)
        print(obj.file)
        file_path = str(obj.file)

        
        path = media_path + file_path
       
        obj_e = HybridAESRSACipher(public_key_loc=public_key, private_key_loc=private_key,
                        public_key_passphrase=password, private_key_passphrase=password)

        # file_path = "G:/Client Work/Assignment Project/WebApp\encrypt/media\encrypt/1.jpg"
        obj_e.encrypt_file(path)
        os.remove(path)
        obj.file = path+".enc"
        obj.save()
    
        messages.success(request,"Successfully Encrypted and Added File")
        return HttpResponseRedirect(reverse('decrypt:userhome'))
      
    return render(request, "multiencryption.html")