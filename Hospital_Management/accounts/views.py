from baseapp.utils import formatResponse
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from hashlib import sha1 as hash_sha1
from hospital.models import Hospital
from hospital.views import AddHospital
from .models import HospitalUser, Role, PasswordRecovery, Permission
from os.path import dirname as os_dirname, abspath as os_abspath
from random import choice as random_choice
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import (api_view, permission_classes)
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from .serializer import HospitalUserSerializer, RoleSerializer, PermissionSerializer, GetCurrentUserSerializer
from rest_framework.views import APIView
from string import ascii_uppercase, digits as string_digits
from sys import exc_info
from Hospital_Management.settings import EMAIL_HOST_USER, OTP_EXPIRE_TIME
from django.core.mail import send_mail, EmailMultiAlternatives
from datetime import datetime, timedelta


def GetCurrentUserData(id, current_role):
    '''
    Method to get current User data
    :param id and current_role:
    :return:
    '''
    user_data = {}
    try:

        usr_obj = HospitalUser.objects.get(id=id)

        if usr_obj:
            srlz = GetCurrentUserSerializer(usr_obj)
            user_data = srlz.data

            try:
                prmsn = current_role.permission.all().values("name")
            except:
                prmsn = None

            user_data['permissions'] = prmsn

        return user_data

    except:
        return user_data


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def login(request):
    """
    method to handle login request
    :param request: email and password
    :return: response set with auth token
    """
    try:

        email = request.data.get("email")
        password = request.data.get("password")

        if email is None or password is None:
            return Response(formatResponse('Please provide both email and password', 'error',
                                           None, status.HTTP_400_BAD_REQUEST))

        user = authenticate(username=email, password=password)

        if not user:
            return Response(formatResponse('Invalid Credentials', 'error',
                                           None, status.HTTP_404_NOT_FOUND))

        token, _ = Token.objects.get_or_create(user=user)
        user_data = GetCurrentUserData(user.id, user.role)
        user_data['token'] = token.key

        return Response(formatResponse('Login successfully', 'success', user_data,
                                       status.HTTP_200_OK))

    except:
        print("--->>", exc_info())
        return Response(formatResponse('Internal Server Error', 'error', None,
                                       status.HTTP_500_INTERNAL_SERVER_ERROR))


def generate_otp(size):
    """method to generate OTP"""
    # Takes random choices from
    # ascii_letters and digits
    generate_pass = ''.join([random_choice(ascii_uppercase + string_digits)
                             for n in range(size)])

    return generate_pass


@api_view(["POST"])
@permission_classes((AllowAny,))
def password_reset_request(request):
    """
    method to handle password reset
    :param request: email and name
    """
    try:
        email_to = request.data.get("email", None)
        name_to = request.data.get("name", None)

        if not email_to:
            msg = 'Email id is required'
            return Response(formatResponse(msg, 'error', None, status.HTTP_400_BAD_REQUEST))

        user_obj = HospitalUser.objects.filter(email=email_to)
        is_exist = user_obj.count()

        if is_exist > 0:
            otp = generate_otp(6)
            root_path = os_dirname(os_dirname(os_abspath(__file__)))
            root_path = str(root_path) + '/accounts/templates/passwordRecovery.html'
            email_content = ''

            with open(root_path, 'r') as myfile:
                email_content = myfile.read()

            email_content = str(email_content).replace("[name]", name_to)
            email_content = str(email_content).replace("[email]", email_to)
            email_content = str(email_content).replace("[otp]", str(otp))
            subject = "Password Reset"

            email = EmailMultiAlternatives(
                subject=subject,
                body="",
                from_email=EMAIL_HOST_USER,
                to=[email_to]
            )
            email.attach_alternative(email_content, 'text/html')
            email.send()

            obj_pr = PasswordRecovery()
            obj_pr.email = email_to
            obj_pr.user_id = user_obj[0].id
            obj_pr.otp = otp
            obj_pr.save()

            return Response(formatResponse('Email sent successfully', 'success', otp,
                                           status.HTTP_200_OK))

        return Response(formatResponse('Email does', 'error', None,
                                       status.HTTP_400_BAD_REQUEST))

    except:
        from sys import exc_info
        print("--->>>", exc_info())
        return Response(formatResponse('Internal Server Error', 'error', None,
                                       status.HTTP_500_INTERNAL_SERVER_ERROR))


@api_view(["POST"])
@permission_classes((AllowAny,))
def password_reset(request):
    """
    method to handle password reset
    :param request: otp ,email and password
    """
    try:
        otp = request.data.get("otp", None)
        password = request.data.get("password", None)
        email = request.data.get("email", None)

        if not otp:
            msg = 'Temporary One time password is required'
            return Response(formatResponse(msg, 'error', None, status.HTTP_400_BAD_REQUEST))

        if not password:
            msg = 'Password is required'
            return Response(formatResponse(msg, 'error', None, status.HTTP_400_BAD_REQUEST))

        if not email:
            msg = 'Email is required'
            return Response(formatResponse(msg, 'error', None, status.HTTP_400_BAD_REQUEST))

        otp_obj = PasswordRecovery.objects.filter(otp=otp, email=email)
        is_exist = otp_obj.count()

        if is_exist > 0:
            otp_created = otp_obj[0].created_at
            otp_created = str(otp_created).split('.')[0]
            otp_created = datetime.strptime(otp_created, "%Y-%m-%d %H:%M:%S")

            current_datetime = datetime.now()
            current_datetime = str(current_datetime).split('.')[0]
            current_datetime = datetime.strptime(current_datetime, "%Y-%m-%d %H:%M:%S")

            expired_at = otp_created+timedelta(hours=OTP_EXPIRE_TIME)

            if expired_at > current_datetime:
                obj_u = HospitalUser.objects.get(id=otp_obj[0].user_id)
                obj_u.set_password(password)
                obj_u.save()
                otp_obj.delete()

                return Response(formatResponse('Password reset successfully', 'success',
                                               None, status.HTTP_200_OK))
            else:
                return Response(formatResponse('Temporary One time password is Expired', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        else:
            return Response(formatResponse('Temporary One time Password or Email is not valid', 'error',
                                           None, status.HTTP_400_BAD_REQUEST))
    except:
        return Response(formatResponse('Internal Server Error', 'error', None,
                                       status.HTTP_500_INTERNAL_SERVER_ERROR))


class ChangePassword(APIView):
    '''
    Method to change user password
    :param request:
    :return:
    '''

    def post(self, request):
        try:
            dataset = dict(request.data)
            if len(dataset) == 0:
                return Response(formatResponse('bad request', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
            msg = ''
            if 'old_password' not in dataset.keys():
                msg = 'Old password is required'
            if 'new_password' not in dataset.keys():
                msg = 'New Password is required'
            if 'confirm_password' not in dataset.keys():
                msg = 'Confirm Password is required'

            if dataset['confirm_password'] != dataset['new_password']:
                msg = 'The new password and the confirmation do not match. Please verify.'

            if msg != '':
                return Response(formatResponse(msg, 'error', None, status.HTTP_400_BAD_REQUEST))

            user = authenticate(username=request.user.email, password=dataset['old_password'])
            if not user:
                return Response(formatResponse("Current Password didn't match", 'error',
                                               None, status.HTTP_404_NOT_FOUND))

            try:
                obj_u = HospitalUser.objects.get(id=request.user.id)
                obj_u.set_password(dataset['new_password'])
                obj_u.save()
                return Response(formatResponse('Password changed successfully, Please login with your new password',
                                               'success', None, status.HTTP_200_OK))
            except:
                return Response(formatResponse("Something went wrong. Please try again.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

        except:
            print("--->>", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))


class RegisterUsers(APIView):
    '''
    Method to Register a user
    :param request:
    :return:
    '''
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:

            user_role = request.user.role.role
            dataset = dict(request.data)

            if 'role_id' not in dataset.keys():
                return Response(formatResponse('Role is required', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            if 'email' not in dataset.keys():
                return Response(formatResponse('Email is required', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            if 'password' not in dataset.keys():
                return Response(formatResponse('Password is required', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            if 'hospital_name' not in dataset.keys():
                return Response(formatResponse('Hospital name is required', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            if dataset['role_id'] == 2:
                if user_role != 'Superadmin':
                    return Response(formatResponse("Sorry you don't have permission", 'error', None,
                                                   status.HTTP_400_BAD_REQUEST))

            if dataset['role_id'] == 1:
                if user_role == 'Worker' or user_role == 'Admin':
                    return Response(formatResponse("Sorry you don't have permission", 'error', None,
                                                   status.HTTP_400_BAD_REQUEST))
            if user_role == 'Worker':
                return Response(formatResponse("Sorry you don't have permission", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            obj = HospitalUserSerializer()
            dataset['password'] = make_password(dataset['password'])
            save_data = obj.create(dataset)
            user_id = save_data.id

            if user_id:
                return Response(formatResponse('User created successfully', 'success',  user_id,
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse('Something went wrong', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:

            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))


class DeleteUser(APIView):
    '''
    Method to delete a user
    :param request:
    :return:
    '''
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            data = dict(request.data)
            delete_ac_id = data['id']
            try:
                ac_obj = HospitalUser.objects.get(id=delete_ac_id)
            except:
                ac_obj = None

            if ac_obj:
                ac_obj.delete()
                return Response(formatResponse('User Deleted successfully', 'success', None,
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse("This user does not exist. Please check again.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))


class HandleRole(APIView):
    '''
    Method to handle Role model
    :param request:
    :return:
    '''
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:

            dataset = dict(request.data)

            current_role = request.user.role
            permissions = current_role.permission.all().values('name')

            if 'role' not in dataset.keys():
                return Response(formatResponse('Role Name is required', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
            if 'permission' not in dataset.keys():
                return Response(formatResponse('Permission is required', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
            role_obj = RoleSerializer()
            add_role = role_obj.create(dataset)
            role_id = add_role.id

            if role_id:
                return Response(formatResponse('Role created successfully', 'success', role_id,
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse("Something went wrong. Please try again.", 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:

            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def get(self, request):
        try:
            data = None

            role_obj = Role.objects.filter()

            if role_obj:
                srlz_obj = RoleSerializer(role_obj, many=True)
                data = srlz_obj.data
                for d in data:
                    prm_detal = []
                    prms = d['permission']
                    for perm in prms:
                        obj = Permission.objects.filter(id=perm).values(
                            "permission_key", "name", 'id')
                        prm_detal.append(obj)
                    d['permission_detail'] = prm_detal

                return Response(formatResponse('Roles found successfully', 'success', data,
                                               status.HTTP_200_OK))

        except:
            print("--error--finding--Roles--", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def put(self, request):
        try:
            role_id = request.GET.get('role_id', None)
            data_set = dict(request.data)

            if not role_id:
                return Response(formatResponse('Please Provide Role ID.', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            role_obj = Role.objects.filter(id=role_id)

            if not role_obj:
                return Response(formatResponse('Provided Role Name id not Valid.', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            srlz_obj = RoleSerializer()
            srlz_data = srlz_obj.update(role_obj[0], data_set)
            updated_data = RoleSerializer(srlz_data).data

            return Response(formatResponse('Role Updated successfully', 'success',  updated_data,
                                           status.HTTP_200_OK))

        except:
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def delete(self, request):
        try:
            role_id = request.GET.get('role_id', None)

            if not role_id:
                return Response(formatResponse('Please Provide Role Id.', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            try:
                role_obj = Role.objects.get(id=role_id)
            except:
                role_obj = None

            if role_obj:
                role_obj.delete()
                return Response(formatResponse('Role deleted successfully', 'success', None,
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse('No Role Found to Delete. ', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

        except:
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))


class HandleHospitalAndAdmin(APIView):
    permission_classes = (IsAuthenticated,)
    '''
    Method to handle Hospital and Admin
    :param request:
    :return:
    '''

    def addAdmin(self, data):
        '''
        Method to add Admin
        :param data:
        :return:
        '''
        try:
            dataset = data
            if_already_exist = HospitalUser.objects.filter(email=dataset['email']).values("id")

            if if_already_exist:
                user_id = if_already_exist[0]['id']
                return Response(formatResponse('User Already Created', 'success',  user_id,
                                               status.HTTP_200_OK))
            else:
                obj = HospitalUserSerializer()
                dataset['password'] = make_password(dataset['password'])
                save_data = obj.create(dataset)
                user_id = save_data.id
                user_name = save_data.name
                print("-->", user_name)
                if user_id:
                    return Response(formatResponse('User created successfully', 'success',  user_id,
                                                   status.HTTP_200_OK))
                else:
                    print("---4--->", exc_info())
                return Response(formatResponse('Something went wrong', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
        except:
            print("---5--->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def DataValidation(self, hospital):
        '''
        Method to check if email and hospital is unique or not :
        :param email , hospital:
        :return:
        '''
        _message = None
        # email_obj = HospitalUser.objects.filter(email=email)
        hospital_obj = Hospital.objects.filter(name=hospital)

        # if email_obj:
        #     _message = "Please choose a different email as the provided email already exists"

        if hospital_obj:
            _message = "Please choose a different Hospital as the provided email already exists"

        else:
            _message = "Success"

        return _message

    def post(self, request):
        try:
            dataset = dict(request.data)
            save_admin = RegisterUsers.post(self, dataset)

            email = dataset['email']
            hospital_name = dataset['hospital']

            is_data_valid = self.DataValidation(hospital_name)

            role_name = dataset['role_id']
            try:
                role_id = Role.objects.get(role=role_name)
                role_id = role_id.id
            except:
                role_id = 3

            if is_data_valid == 'Success':
                pswrd = 'password'
                data = {'name': dataset['admin_name'], 'role_id': role_id,
                        'email': email, 'password': pswrd, 'is_admin': dataset['is_admin'], 'profile_image': dataset['profile_image'], 'age': dataset['age'], 'blood_group': dataset['blood_group']}

                print("-->", data)
                save_admin = self.addAdmin(data)
                admin_id = save_admin.data['data']

                if admin_id:
                    hospital_dict = {'admin_id': admin_id, 'admin_email': email,
                                     'name': hospital_name, 'address': dataset['address']}
                    add_hospital = AddHospital(hospital_dict)

                    if add_hospital:
                        return Response(formatResponse('Admin and Hospital created successfully.', 'success', {"Admin": admin_id, "hospital": add_hospital},
                                                       status.HTTP_200_OK))
                    else:
                        try:
                            ac_obj = HospitalUser.objects.get(id=admin_id)
                        except:
                            ac_obj = None

                        if ac_obj:
                            ac_obj.delete()

                        return Response(formatResponse('Unable to create , please try again in some time.', 'error', None,
                                                       status.HTTP_400_BAD_REQUEST))
                else:
                    print("---1--->", exc_info())
                    return Response(formatResponse('Something went wrong', 'error', None,
                                                   status.HTTP_400_BAD_REQUEST))

            else:
                print("---2--->", exc_info())
                return Response(formatResponse(is_data_valid, 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

        except:

            print("---3--->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def get(self, request):
        try:
            usr_obj = HospitalUser.objects.filter()

            srlz_obj = GetCurrentUserSerializer(usr_obj, many=True)
            data = srlz_obj.data

            return Response(formatResponse('Users found successfully', 'success', data,
                                           status.HTTP_200_OK))

        except:
            print("--->", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    # def put(self,request)


class handlePermissions(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            data_dict = dict(request.data)
            per_key = data_dict['permission_key']

            check_key_exist = Permission.objects.filter(permission_key=per_key)

            if check_key_exist:
                return Response(formatResponse('The permission key already exists. Please choose a different key or utilize the existing permission.', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            else:
                srlz_obj = PermissionSerializer()
                add_permission = srlz_obj.create(data_dict)
                permission_key = add_permission.permission_key
                if permission_key:
                    return Response(formatResponse('Permission created successfully', 'success', {"key": permission_key},
                                                   status.HTTP_200_OK))

        except:
            print("--error--adding--permissions--", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def get(self, request):
        try:
            data = None

            per_obj = Permission.objects.filter()

            if per_obj:
                srlz_obj = PermissionSerializer(per_obj, many=True)
                data = srlz_obj.data
                return Response(formatResponse('Permissions found successfully', 'success', data,
                                               status.HTTP_200_OK))

        except:
            print("--error--finding--permissions--", exc_info())
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def delete(self, request):
        try:
            permission_id = request.GET.get('permission_id', None)

            if not permission_id:
                return Response(formatResponse('Please Provide Permission ', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            try:
                per_obj = Permission.objects.get(id=permission_id)
            except:
                per_obj = None

            if per_obj:
                per_obj.delete()
                return Response(formatResponse('Permissions deleted successfully', 'success', None,
                                               status.HTTP_200_OK))
            else:
                return Response(formatResponse('No Permission Found to Delete. ', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

        except:
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))

    def put(self, request):
        try:
            permission_id = request.GET.get('permission_id', None)
            data_set = dict(request.data)

            if not permission_id:
                return Response(formatResponse('Please Provide Role ID.', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))

            try:
                per_obj = Permission.objects.get(id=permission_id)
            except:
                per_obj = None

            if not per_obj:
                return Response(formatResponse('Given Role Id id not valid.', 'error', None,
                                               status.HTTP_400_BAD_REQUEST))
            srlz_obj = PermissionSerializer()
            srlz_data = srlz_obj.update(srlz_obj, data_set)
            updated_data = PermissionSerializer(srlz_data).data

            return Response(formatResponse('Permission Updated successfully', 'success',  updated_data,
                                           status.HTTP_200_OK))

        except:
            return Response(formatResponse('Internal Server Error', 'error', None,
                                           status.HTTP_500_INTERNAL_SERVER_ERROR))
