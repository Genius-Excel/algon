from django.contrib.auth import get_user_model
from rest_framework.permissions import BasePermission

from core.utils import get_user_role


class IsApplicantUser(BasePermission):
    """
    Custom permission class to allow only the authenticated user to take view data
    """

    def has_permission(self, request, view):
        # Allow access only to authenticated users
        role = get_user_role(request.user)
        return role == "applicant"

    def has_object_permission(self, request, view, obj):
        # Check if the user is trying to access their own data
        return obj.applicant == request.user


class IsLGAdmin(BasePermission):
    """
    Custom permission class to allow only local government admins to access certain actions.
    """

    def has_permission(self, request, view):
        # Check if the user has the 'lg_admin' role
        role = get_user_role(request.user)
        return role == "lg_admin"

    def has_object_permission(self, request, view, obj):
        # check if the user can approve requests for their local government
        return (
            request.user.admin_permissions.local_governemt
            == obj.local_government
        )


class CanViewAndApproveRequests(BasePermission):
    """
    Custom permission class to allow only users with approval rights to approve requests.
    """

    def has_permission(self, request, view) -> bool:
        # Check if the user has the 'lg_admin' or 'super_admin' role
        role = get_user_role(request.user)
        return role in ["lg_admin", "super_admin"]

    def has_object_permission(self, request, view, obj) -> bool:
        # Additional object-level permission checks can be added here
        user = request.user
        role = get_user_role(user)
        if role == "super_admin":
            return True
        admin_perms = user.admin_permissions.all()
        allowed_lgs = admin_perms.values_list("local_government", flat=True)
        return obj.local_government.id in allowed_lgs


class CanExportCSV(BasePermission):

    def has_permission(self, request, view):
        role = get_user_role(request.user)
        return role in ["lg_admin", "super_admin"]

    def has_object_permission(self, request, view, obj):
        """
        Check if the user has export permissions for the local government.
        """
        return request.user.admin_permissions.filter(
            local_government=obj.local_government, can_export=True
        ).exists()
