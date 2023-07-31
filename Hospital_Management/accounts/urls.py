from django.urls import path

from accounts.views import login, RegisterUsers, DeleteUser, HandleRole, HandleHospitalAndAdmin, handlePermissions, ChangePassword, password_reset_request, password_reset

urlpatterns = [
    path('login/', login),
    path('register/', RegisterUsers.as_view()),
    path('delete/', DeleteUser.as_view()),
    path('add-role/', HandleRole.as_view()),
    path('change-password/', ChangePassword.as_view()),
    path('add-hospital-admin/', HandleHospitalAndAdmin.as_view()),
    path('forgot-password/', password_reset_request),
    path('reset-password/', password_reset),
    path('handle-permissions/', handlePermissions.as_view())
]
