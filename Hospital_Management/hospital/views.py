from django.shortcuts import render
from .serializer import HospitalSerializer
from sys import exc_info
# Create your views here.


def HandleHospitalData(dataSet):
    "Function to Add Hospital"

    try:
        data_to_save = dataSet
        srlz_obj = HospitalSerializer()
        save_hospital = srlz_obj.create(data_to_save)
        if save_hospital.id:
            return save_hospital.id

        else:
            return None

    except:
        print("-->", exc_info())
        return None
