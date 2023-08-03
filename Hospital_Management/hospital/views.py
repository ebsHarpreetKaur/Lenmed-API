from .serializer import HospitalSerializer
from sys import exc_info
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from baseapp.utils import formatResponse
from sys import exc_info
from .models import Hospital
from accounts.models import HospitalUser
from logs.LogHandler import LogHelper

# Create your views here.


def AddHospital(dataSet):
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
        print("-error in adding hospital->", exc_info())
        return None


class HandleHospitalData(APIView):
    '''
    Method to handle Hospital model
    :param request:
    :return:
    '''
    permission_classes = (IsAuthenticated,)
    objLog = LogHelper('hospital', 'HandleHospitalData')

    def getHospitalObject(sef, id):
        try:
            hsptl_obj = Hospital.objects.filter(admin_id=id)
            if hsptl_obj:
                return hsptl_obj
            else:
                return None
        except:
            return None

    def getUserObject(sef, id):
        try:
            user_obj = HospitalUser.objects.filter(id=id)

            if user_obj:
                return user_obj
            else:
                return None
        except:
            return None

    def get(self, request):
        try:
            user_role = request.user.role.role
            user_id = request.user.id
            if user_role == 'Superadmin':
                hsptl_obj = Hospital.objects.filter()
            else:
                hsptl_obj = self.getHospitalObject(user_id)

            if hsptl_obj:
                srlz_obj = HospitalSerializer(hsptl_obj, many=True)
                Hospital_data = srlz_obj.data

                return Response(formatResponse('Data found successfully', 'success',  Hospital_data,
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse('No data found', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            self.objLog.doLog(exc_info(), 'error')
            print("-error in fetching Hospital Data->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def put(self, request):
        try:
            user_id = request.user.id
            data_dict = request.data

            if_alredy_exist = Hospital.objects.filter(id != user_id, name=data_dict)

            if if_alredy_exist:
                return Response(formatResponse('Same Hospital is registered to another user, Please Change the Hospital Name', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            hsptl_obj = self.getHospitalObject(user_id)
            if hsptl_obj:
                srlz_obj = HospitalSerializer()
                srlz_data = srlz_obj.update(hsptl_obj[0], data_dict)
                updated_data = HospitalSerializer(srlz_data).data

                if updated_data:
                    return Response(formatResponse('Data Updated successfully', 'success',  updated_data,
                                                   status.HTTP_200_OK))
                else:
                    return Response(formatResponse('Something went wrong', 'error', None,
                                                   status.HTTP_400_BAD_REQUEST))

        except:
            self.objLog.doLog(exc_info(), 'error')
            print("-error in Updating Hospital Data->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def delete(self, request):
        try:
            user_role = request.user.role.role
            id_to_delete = request.GET.get("id", None)
            if user_role == 'Superadmin':
                hsptl_obj = self.getHospitalObject(id_to_delete)
                user_obj = self.getHospitalObject(id_to_delete)

                if hsptl_obj and user_obj:
                    hsptl_obj.delete()
                    user_obj.delete()

                    return Response(formatResponse('Hospital Deleted successfully', 'success',  None,
                                                   status.HTTP_200_OK))
                else:
                    return Response(formatResponse("The Hospital you wish to remove does not exist. Kindly verify and attempt again.", 'error', None,
                                                   status.HTTP_400_BAD_REQUEST))
            else:
                return Response(formatResponse("Apologies, but you do not have the necessary permissions to delete the hospital.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            self.objLog.doLog(exc_info(), 'error')
            print("-error in removing Hospital Data->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))
