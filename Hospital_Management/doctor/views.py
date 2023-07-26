from .serializer import DoctorSerializer
from sys import exc_info
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from baseapp.utils import formatResponse
from sys import exc_info
from .models import Doctor
from accounts.models import HospitalUser, Role
from hospital.models import Hospital


class HandleDoctorData(APIView):
    permission_classes = (IsAuthenticated,)
    '''
    Method to handle Hospital and Admin
    :param request:
    :return:
    '''

    def DataValidation(self, email):
        '''
        Method to check if Doctor's email is unique or not :
        :param email :
        :return:
        '''
        _message = None
        email_obj = Doctor.objects.filter(email=email)

        if email_obj:
            _message = "Please choose a different email as the provided email already exists"

        else:
            _message = "Success"

        return _message

    def getDoctorObject(self, id):
        try:
            doct_obj = Doctor.objects.filter(id=id)
            if doct_obj:
                return doct_obj
            else:
                return None
        except:
            return None

    def post(self, request):
        try:
            data = dict(request.data)
            user_id = request.user.id
            user_role = request.user.role.role
            is_data_valid = self.DataValidation(data['email'])

            if is_data_valid != "Success":
                return Response(formatResponse(is_data_valid, 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            if user_role == 'Admin':
                hsptl_obj = Hospital.objects.filter(admin_id=user_id).values("id")

                try:
                    role_id = Role.objects.get(role=data['role_id'])
                    role_id = role_id.id
                except:
                    role_id = 3

                data['admin_id'] = user_id
                data['hospital_id'] = hsptl_obj[0]["id"]
                data['role_id'] = role_id

                srlz_obj = DoctorSerializer()
                save_doctor = srlz_obj.create(data)
                doctor_id = save_doctor.id

                return Response(formatResponse('Doctor Saved successfully', 'success', {"doctor_id": doctor_id},
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse("Apologies, but you do not have the necessary permissions to Add Doctor.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            print("--eroor in adding Doctor->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def get(self, request):
        try:
            user_role = request.user.role.role
            user_id = request.user.id
            doctor_id = request.GET.get("id", None)

            if user_role == 'Admin' and doctor_id == None:
                doct_obj = Doctor.objects.filter(admin_id=user_id)
            else:
                doct_obj = self.getDoctorObject(doctor_id)

            if doct_obj:
                srlz_obj = DoctorSerializer(doct_obj, many=True)
                Doctor_data = srlz_obj.data

                return Response(formatResponse('Data found successfully', 'success',  Doctor_data,
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse('No data found', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            print("-error in fetching Doctor Data->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def put(self, request):
        try:
            user_role = request.user.role.role
            data_dict = request.data
            doct_id = request.GET.get("id", None)

            if user_role == "Admin":

                if doct_id:
                    doct_obj = self.getDoctorObject(doct_id)

                    if doct_obj:
                        srlz_obj = DoctorSerializer()
                        srlz_data = srlz_obj.update(doct_obj[0], data_dict)
                        updated_data = DoctorSerializer(srlz_data).data

                        if updated_data:
                            return Response(formatResponse('Data Updated successfully', 'success',  updated_data,
                                                           status.HTTP_200_OK))
                        else:
                            return Response(formatResponse('Something went wrong', 'error', None,
                                                           status.HTTP_400_BAD_REQUEST))

                    else:
                        return Response(formatResponse('No valid Doctor found. Please ensure that you have provided the correct ID.', 'error', None,
                                                       status.HTTP_400_BAD_REQUEST))

                else:
                    return Response(formatResponse('Please provide Doctor ID.', 'error', None,
                                                   status.HTTP_400_BAD_REQUEST))
            else:
                return Response(formatResponse("Apologies, but you do not have the necessary permissions to Update Doctor.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            print("-error in Updating Hospital Data->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def delete(self, request):
        try:
            user_role = request.user.role.role
            id_to_delete = request.GET.get("id", None)

            if user_role == 'Admin':
                doct_obj = self.getDoctorObject(id_to_delete)

                if doct_obj:
                    doct_obj.delete()

                    return Response(formatResponse('Doctor Removed successfully', 'success',  None,
                                                   status.HTTP_200_OK))
                else:
                    return Response(formatResponse("The Doctor you wish to remove does not exist. Kindly verify and attempt again.", 'error', None,
                                                   status.HTTP_400_BAD_REQUEST))
            else:
                return Response(formatResponse("Apologies, but you do not have the necessary permissions to Rrmove the Doctor.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            print("-error in removing Hospital Data->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))
