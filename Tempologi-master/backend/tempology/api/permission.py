from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import User, Wallet, KYCDocument, CorporateProfile


class IsConsignee(BasePermission):
    """
    Permission class for consignee users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'consignee'
        )


class IsTruckOwner(BasePermission):
    """
    Permission class for truck owner users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'truck_owner'
        )


class IsTransporter(BasePermission):
    """
    Permission class for transporter users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'transporter'
        )


class IsCorporate(BasePermission):
    """
    Permission class for corporate users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'corporate'
        )


class IsAdmin(BasePermission):
    """
    Permission class for admin users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'admin'
        )


class IsDriver(BasePermission):
    """
    Permission class for driver users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'driver'
        )


class IsConsigneeOrCorporate(BasePermission):
    """
    Permission class for consignee or corporate users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role in ['consignee', 'corporate']
        )


class IsTruckOwnerOrTransporter(BasePermission):
    """
    Permission class for truck owner or transporter users only.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role in ['truck_owner', 'transporter']
        )


class IsVehicleOwner(BasePermission):
    """
    Permission class to check if user is the owner of a specific vehicle.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any vehicle
        if request.user.role == 'admin':
            return True
        # Check if user is the owner
        return obj.owner == request.user


class IsLoadOwner(BasePermission):
    """
    Permission class to check if user is the owner of a specific load.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any load
        if request.user.role == 'admin':
            return True
        # Check if user is the consignee who posted the load
        return obj.consignee == request.user


class IsBookingParticipant(BasePermission):
    """
    Permission class to check if user is a participant in a booking.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any booking
        if request.user.role == 'admin':
            return True
        # Check if user is consignee, transporter, or driver
        return request.user in [obj.consignee, obj.transporter, obj.driver]


class IsDocumentOwner(BasePermission):
    """
    Permission class to check if user owns a KYC document.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any document
        if request.user.role == 'admin':
            return True
        # Check if user owns the document
        return obj.user == request.user


class IsAddressOwner(BasePermission):
    """
    Permission class to check if user owns an address.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any address
        if request.user.role == 'admin':
            return True
        # Check if user owns the address
        return obj.user == request.user


class IsBidRelatedToUser(BasePermission):
    """
    Permission class to check if user is related to a bid.
    Either as the transporter who placed the bid or the consignee of the load.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any bid
        if request.user.role == 'admin':
            return True
        # Check if user is the transporter who placed the bid or the consignee of the load
        return obj.transporter == request.user or obj.load.consignee == request.user


class IsScheduleOwner(BasePermission):
    """
    Permission class to check if user owns a vehicle schedule.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any schedule
        if request.user.role == 'admin':
            return True
        # Check if user owns the vehicle (and thus the schedule)
        return obj.vehicle.owner == request.user


class IsRatingRelatedToUser(BasePermission):
    """
    Permission class to check if user is related to a rating.
    Either as the reviewer or reviewee.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any rating
        if request.user.role == 'admin':
            return True
        # Check if user is the reviewer or reviewee
        return obj.reviewer == request.user or obj.reviewee == request.user


class IsDisputeRaisedByUser(BasePermission):
    """
    Permission class to check if user raised a dispute.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any dispute
        if request.user.role == 'admin':
            return True
        # Check if user raised the dispute
        return obj.raised_by == request.user


class IsWalletOwner(BasePermission):
    """
    Permission class to check if user owns a wallet.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any wallet
        if request.user.role == 'admin':
            return True
        # Check if user owns the wallet
        return obj.user == request.user


class IsNotificationOwner(BasePermission):
    """
    Permission class to check if notification belongs to user.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any notification
        if request.user.role == 'admin':
            return True
        # Check if notification belongs to user
        return obj.user == request.user


class IsPaymentRelatedToUser(BasePermission):
    """
    Permission class to check if user is related to a payment.
    Either as payer or payee.
    """

    def has_object_permission(self, request, view, obj):
        # Admin can access any payment
        if request.user.role == 'admin':
            return True
        # Check if user is payer or payee
        return obj.payer == request.user or obj.payee == request.user


class CanManageVehicles(BasePermission):
    """
    Permission class for users who can manage vehicles (truck owners, transporters, admin).
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['truck_owner', 'transporter', 'admin'])
        )


class CanPostLoads(BasePermission):
    """
    Permission class for users who can post loads (consignees, corporate, admin).
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['consignee', 'corporate', 'admin'])
        )


class CanPlaceBids(BasePermission):
    """
    Permission class for users who can place bids (transporters, truck owners, admin).
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['transporter', 'truck_owner', 'admin'])
        )


class CanViewTracking(BasePermission):
    """
    Permission class for users who can view tracking (booking participants, admin).
    """

    def has_object_permission(self, request, view, obj):
        # Admin can view any tracking
        if request.user.role == 'admin':
            return True
        # Check if user is participant in the booking
        return request.user in [obj.booking.consignee, obj.booking.transporter, obj.booking.driver]


class CanUpdateTracking(BasePermission):
    """
    Permission class for users who can update tracking (transporter, driver, admin).
    """

    def has_object_permission(self, request, view, obj):
        # Admin can update any tracking
        if request.user.role == 'admin':
            return True
        # Check if user is transporter or driver
        return request.user in [obj.booking.transporter, obj.booking.driver]


class IsOwnerOrReadOnly(BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    Read permissions are allowed to any request.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in SAFE_METHODS:
            return True

        # Admin can edit any object
        if request.user.role == 'admin':
            return True

        # Write permissions are only allowed to the owner of the object
        if hasattr(obj, 'user'):
            return obj.user == request.user
        elif hasattr(obj, 'owner'):
            return obj.owner == request.user
        elif hasattr(obj, 'consignee'):
            return obj.consignee == request.user
        elif hasattr(obj, 'transporter'):
            return obj.transporter == request.user
        elif hasattr(obj, 'raised_by'):
            return obj.raised_by == request.user
        elif hasattr(obj, 'reviewer'):
            return obj.reviewer == request.user

        return False


class HasKYCCompleted(BasePermission):
    """
    Permission class to check if user has completed KYC verification.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Admin doesn't need KYC
        if request.user.role == 'admin':
            return True

        # Check if user is verified
        if not request.user.is_verified:
            return False

        # Check if user has at least one approved KYC document
        has_approved_kyc = KYCDocument.objects.filter(
            user=request.user,
            verification_status='approved'
        ).exists()

        return has_approved_kyc


class HasWallet(BasePermission):
    """
    Permission class to check if user has a wallet.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        try:
            wallet = Wallet.objects.get(user=request.user)
            return True
        except Wallet.DoesNotExist:
            return False


class HasSufficientBalance(BasePermission):
    """
    Permission class to check if user has sufficient wallet balance.
    Requires amount in request data.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        # Only check for POST and PUT requests
        if request.method not in ['POST', 'PUT']:
            return True

        try:
            amount = float(request.data.get('amount', 0))
            wallet = Wallet.objects.get(user=request.user)
            return wallet.balance >= amount
        except (Wallet.DoesNotExist, ValueError, TypeError):
            return False


class IsActiveUser(BasePermission):
    """
    Permission class to check if user account is active.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.is_active and
            request.user.status == 'active'
        )


class IsVerifiedUser(BasePermission):
    """
    Permission class to check if user account is verified.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.is_verified
        )


class IsCorporateWithCreditLimit(BasePermission):
    """
    Permission class for corporate users with credit limit check.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        if request.user.role != 'corporate':
            return False

        try:
            corporate_profile = CorporateProfile.objects.get(user=request.user)
            # Check if credit limit is sufficient for transaction
            if request.method in ['POST']:
                amount = float(request.data.get('amount', 0))
                return corporate_profile.credit_limit >= amount
            return True
        except (CorporateProfile.DoesNotExist, ValueError, TypeError):
            return False


class CanAccessBookingDetails(BasePermission):
    """
    Permission class to check if user can access booking details.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated
        )

    def has_object_permission(self, request, view, obj):
        # Admin can access any booking
        if request.user.role == 'admin':
            return True

        # Users can access bookings they are part of
        return request.user in [obj.consignee, obj.transporter, obj.driver]


class CanUpdateBookingStatus(BasePermission):
    """
    Permission class to check if user can update booking status.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated
        )

    def has_object_permission(self, request, view, obj):
        # Admin can update any booking
        if request.user.role == 'admin':
            return True

        # Transporter can update booking status
        if request.user == obj.transporter:
            return True

        # Driver can update booking status during transit
        if request.user == obj.driver and obj.booking_status in ['in_transit', 'at_delivery']:
            return True

        return False


class CanManageDrivers(BasePermission):
    """
    Permission class for users who can manage drivers (transporter, admin).
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['transporter', 'admin'])
        )


class CanViewReports(BasePermission):
    """
    Permission class for users who can view reports (admin only).
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'admin'
        )


class CanManageDisputes(BasePermission):
    """
    Permission class for users who can manage disputes (admin only).
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            request.user.role == 'admin'
        )


# Combined permission classes for common scenarios
class CanManageOwnVehicles(IsTruckOwnerOrTransporter, IsVehicleOwner):
    """
    Combined permission: user must be truck owner/transporter and owner of the vehicle.
    """

    def has_object_permission(self, request, view, obj):
        return IsVehicleOwner().has_object_permission(request, view, obj)


class CanManageOwnLoads(CanPostLoads, IsLoadOwner):
    """
    Combined permission: user must be able to post loads and be the load owner.
    """

    def has_object_permission(self, request, view, obj):
        return IsLoadOwner().has_object_permission(request, view, obj)


class CanAccessBooking(IsBookingParticipant):
    """
    Permission: user must be a participant in the booking.
    """
    pass


class CanManageOwnKYC(IsDocumentOwner):
    """
    Permission: user must own the KYC document.
    """
    pass


class CanManageOwnAddress(IsAddressOwner):
    """
    Permission: user must own the address.
    """
    pass


class CanManageOwnSchedule(IsScheduleOwner):
    """
    Permission: user must own the vehicle schedule.
    """
    pass


class CanManageOwnWallet(IsWalletOwner):
    """
    Permission: user must own the wallet.
    """
    pass


class CanViewOwnNotifications(IsNotificationOwner):
    """
    Permission: user must own the notification.
    """
    pass


class IsTransporterOrAdmin(BasePermission):
    """
    Permission: user must be transporter or admin.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['transporter', 'admin'])
        )


class IsConsigneeOrAdmin(BasePermission):
    """
    Permission: user must be consignee or admin.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['consignee', 'admin'])
        )


class IsTruckOwnerOrAdmin(BasePermission):
    """
    Permission: user must be truck owner or admin.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['truck_owner', 'admin'])
        )


class IsCorporateOrAdmin(BasePermission):
    """
    Permission: user must be corporate or admin.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['corporate', 'admin'])
        )


class IsDriverOrAdmin(BasePermission):
    """
    Permission: user must be driver or admin.
    """

    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.is_authenticated and
            (request.user.role in ['driver', 'admin'])
        )