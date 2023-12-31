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

    def getHospitalObject(sef, hos_id):
        try:
            hsptl_obj = Hospital.objects.filter(id=hos_id)
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
            hospital_id = request.GET.get('hospital_id', None)

            if hospital_id:
                hsptl_obj = self.getHospitalObject(hospital_id)

            elif user_role == 'Superadmin':
                hsptl_obj = Hospital.objects.filter()

            else:
                hsptl_obj = Hospital.objects.filter(user_id=user_id)

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
            hospital_id = request.GET.get['hospital_id', None]
            data_dict = request.data

            if hospital_id:
                hsptl_obj = self.getHospitalObject(hospital_id)

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
            else:
                return Response(formatResponse('No hospital found.', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

        except:
            self.objLog.doLog(exc_info(), 'error')
            print("-error in Updating Hospital Data->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def delete(self, request):
        try:
            user_role = request.user.role.role

            id_to_delete = request.GET.get("hospital_id", None)
            if user_role == 'Superadmin':
                # hsptl_obj = self.getHospitalObject(id_to_delete,id_to_delete)
                hsptl_obj = Hospital.objects.filter(id=id_to_delete)

                if hsptl_obj:
                    hsptl_obj.delete()

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

    def post(self, request):
        try:
            data = request.data
            hospital_exist = Hospital.objects.filter(name=data['name'])

            if hospital_exist:
                return Response(formatResponse("Hospital with same name alredy exist.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
            valid_user = HospitalUser.objects.filter(id=data['admin_id'], email=data['admin_email'])

            if not valid_user:
                return Response(formatResponse("No user found with given id , Kindly verify and attempt again.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            srlz_obj = HospitalSerializer()
            save_data = srlz_obj.create(data)
            hospital_id = save_data.id

            return Response(formatResponse('Hospital Added successfully', 'success',  {"hospital_id": hospital_id},
                                           status.HTTP_200_OK))

        except:
            print("-->", exc_info())
            self.objLog.doLog(exc_info(), 'error')
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))
