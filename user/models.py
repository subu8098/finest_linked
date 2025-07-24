from django.db import models

class User(models.Model):
    id = models.AutoField(primary_key=True)
    name= models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password= models.CharField(max_length=100)
    about=models.TextField(blank=True, null=True)
    profile=models.URLField(blank=True, null=True)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    is_deleted=models.BooleanField(default=False)

    def __str__(self):
        return self.email
    

class BlacklistedToken(models.Model):
    token = models.CharField(max_length=255, unique=True)  
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

