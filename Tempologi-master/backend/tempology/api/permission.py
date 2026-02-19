from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'


class IsConsignee(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'consignee'


class IsTruckOwner(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'truck_owner'


class IsTransporter(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'transporter'


class IsCorporate(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'corporate'


class IsDriver(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'driver'


class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'owner'):
            return obj.owner == request.user
        elif hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'consignee'):
            return obj.consignee == request.user
        return False


class IsConsigneeOrCorporate(BasePermission):
    def has_permission(self, request, view):
        return (request.user.is_authenticated and
                request.user.role in ['consignee', 'corporate'])


class IsTransporterOrOwner(BasePermission):
    def has_permission(self, request, view):
        return (request.user.is_authenticated and
                request.user.role in ['transporter', 'truck_owner'])


class IsVehicleOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user


class IsLoadOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return obj.consignee == request.user


class IsBookingParticipant(BasePermission):
    def has_object_permission(self, request, view, obj):
        user = request.user
        return (obj.consignee == user or
                obj.transporter == user or
                obj.driver == user)


class CanManageKYC(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.role == 'admin':
            return True
        return obj.user == request.user


class CanViewTracking(BasePermission):
    def has_object_permission(self, request, view, obj):
        booking = obj if hasattr(obj, 'consignee') else obj.booking
        user = request.user
        return (booking.consignee == user or
                booking.transporter == user or
                booking.driver == user)


class CanUpdateTracking(BasePermission):
    def has_object_permission(self, request, view, obj):
        booking = obj if hasattr(obj, 'consignee') else obj.booking
        user = request.user
        return (booking.transporter == user or booking.driver == user)