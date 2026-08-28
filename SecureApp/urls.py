from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
			path("Signup.html", views.Signup, name="Signup"),
			path("SignupAction", views.SignupAction, name="SignupAction"),	    	
			path("UserLogin.html", views.UserLogin, name="UserLogin"),
			path("UserLoginAction", views.UserLoginAction, name="UserLoginAction"),
			path("UploadFile.html", views.UploadFile, name="UploadFile"),
			path("UploadAction", views.UploadAction, name="UploadAction"),
			path("DownloadFile", views.DownloadFile, name="DownloadFile"),
			path("DownloadFileAction", views.DownloadFileAction, name="DownloadFileAction"),
			path("FileIntegrity", views.FileIntegrity, name="FileIntegrity"),
			path("FileIntegrityAction", views.FileIntegrityAction, name="FileIntegrityAction"),
]