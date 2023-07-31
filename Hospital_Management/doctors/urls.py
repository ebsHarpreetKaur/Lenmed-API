from django.urls import path
from .views import HandleDoctorData

urlpatterns = [
    path('handle-doctor/', HandleDoctorData.as_view()),
]
