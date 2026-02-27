from rest_framework.permissions import BasePermission
from .models import *


class IsActiveUser(BasePermission):
    """Check if user account is active"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.is_active and request.user.status == 'active')


class IsAdmin(BasePermission):
    """Check if user is admin"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role == 'admin' and request.user.is_staff)


class IsConsignee(BasePermission):
    """Check if user is consignee"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role == 'consignee')


class IsTransporter(BasePermission):
    """Check if user is transporter"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role == 'transporter')


class IsTruckOwner(BasePermission):
    """Check if user is truck owner"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role == 'truck_owner')


class IsCorporate(BasePermission):
    """Check if user is corporate"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role == 'corporate')


class IsDriver(BasePermission):
    """Check if user is driver"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role == 'driver')


class IsConsigneeOrCorporate(BasePermission):
    """Check if user is consignee or corporate"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role in ['consignee', 'corporate'])


class IsTruckOwnerOrTransporter(BasePermission):
    """Check if user is truck owner or transporter"""

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and
                    request.user.role in ['truck_owner', 'transporter'])


# ============ OBJECT LEVEL PERMISSIONS ============

class IsDocumentOwner(BasePermission):
    """Check if user owns the KYC document"""

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


class IsAddressOwner(BasePermission):
    """Check if user owns the address"""

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


class IsVehicleOwner(BasePermission):
    """Check if user owns the vehicle"""

    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user


class IsScheduleOwner(BasePermission):
    """Check if user owns the schedule (via vehicle)"""

    def has_object_permission(self, request, view, obj):
        return obj.vehicle.owner == request.user


class IsLoadOwner(BasePermission):
    """Check if user owns the load"""

    def has_object_permission(self, request, view, obj):
        return obj.consignee == request.user


class IsBookingParticipant(BasePermission):
    """Check if user is participant in booking"""

    def has_object_permission(self, request, view, obj):
        return request.user in [obj.consignee, obj.transporter, obj.driver]


class IsBookingDriver(BasePermission):
    """Check if user is the assigned driver for a booking"""

    def has_object_permission(self, request, view, obj):
        return obj.driver == request.user


class IsNotificationOwner(BasePermission):
    """Check if notification belongs to user"""

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user


class HasWallet(BasePermission):
    """Check if user has a wallet"""

    def has_permission(self, request, view):
        return hasattr(request.user, 'wallet')


# ============ LOAD REQUEST PERMISSIONS ============

class IsLoadRequestParticipant(BasePermission):
    """Check if user is either requester or load owner"""

    def has_object_permission(self, request, view, obj):
        return request.user in [obj.requester, obj.load.consignee]


class IsLoadRequestRequester(BasePermission):
    """Check if user is the requester"""

    def has_object_permission(self, request, view, obj):
        return obj.requester == request.user


class IsLoadRequestReceiver(BasePermission):
    """Check if user is the load owner (consignee)"""

    def has_object_permission(self, request, view, obj):
        return obj.load.consignee == request.user