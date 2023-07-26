from django.urls import path
from .views import HandleHospitalData

urlpatterns = [
    path('handle-hospital/', HandleHospitalData.as_view()),
]
