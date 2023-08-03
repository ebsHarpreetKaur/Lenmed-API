from django.urls import path
from .views import HandleDoctorData, HandleDoctorAndHospital

urlpatterns = [
    path('handle-doctor/', HandleDoctorData.as_view()),
    path('handle-assign-doctor/', HandleDoctorAndHospital.as_view()),
]
