from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class FileList(models.Model):
    name = models.CharField(max_length=200)
    file = models.FileField(upload_to='encrypt/')
    objects = models.Manager()
    user = models.ForeignKey(User, related_name="user_file", on_delete=models.CASCADE)

    def __str__(self):
        return self.name

class History(models.Model):
    file = models.ForeignKey(FileList, related_name="filelist", on_delete=models.PROTECT)
    date = models.DateTimeField(auto_now_add=True)
    objects = models.Manager()

    def __str__(self):
        return str(self.date)
    

