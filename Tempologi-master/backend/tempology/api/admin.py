from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from .models import *


# ============ CUSTOM USER ADMIN ============
class UserAdmin(BaseUserAdmin):
    """Custom User Admin for the custom User model"""

    list_display = ['id', 'full_name', 'email', 'phone_number', 'role', 'status', 'is_verified', 'is_active',
                    'created_at']
    list_filter = ['role', 'status', 'is_verified', 'is_active', 'created_at']
    search_fields = ['full_name', 'email', 'phone_number']
    ordering = ['-created_at']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('full_name', 'phone_number', 'role', 'profile_image', 'status')}),
        ('Permissions',
         {'fields': ('is_active', 'is_staff', 'is_superuser', 'is_verified', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'full_name', 'phone_number', 'role', 'password1', 'password2', 'is_active', 'is_staff',
                       'is_superuser'),
        }),
    )

    readonly_fields = ['created_at', 'updated_at', 'last_login']

    def profile_image_preview(self, obj):
        if obj.profile_image:
            return format_html('<img src="{}" width="50" height="50" style="border-radius: 50%;" />',
                               obj.profile_image.url)
        return "No Image"

    profile_image_preview.short_description = 'Profile Image'


# ============ OTP ADMIN ============
class OTPAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'phone_number', 'otp', 'otp_type', 'is_used', 'expires_at', 'created_at']
    list_filter = ['otp_type', 'is_used', 'created_at']
    search_fields = ['email', 'phone_number', 'otp']
    ordering = ['-created_at']
    readonly_fields = ['created_at']

    def is_expired_display(self, obj):
        return obj.is_expired()

    is_expired_display.boolean = True
    is_expired_display.short_description = 'Expired'


# ============ CORPORATE PROFILE ADMIN ============
class CorporateProfileAdmin(admin.ModelAdmin):
    list_display = ['corporate_id', 'user', 'company_name', 'gst_number', 'contact_person', 'credit_limit']
    list_filter = ['contract_start_date', 'contract_end_date']
    search_fields = ['company_name', 'gst_number', 'user__email', 'user__full_name']
    raw_id_fields = ['user']

    def user_email(self, obj):
        return obj.user.email

    user_email.short_description = 'Email'


# ============ KYC DOCUMENT ADMIN ============
class KYCDocumentAdmin(admin.ModelAdmin):
    list_display = ['doc_id', 'user', 'document_type', 'document_number', 'verification_status', 'expiry_date',
                    'uploaded_at']
    list_filter = ['document_type', 'verification_status', 'uploaded_at']
    search_fields = ['user__email', 'user__full_name', 'document_number']
    raw_id_fields = ['user']
    readonly_fields = ['uploaded_at']

    actions = ['approve_documents', 'reject_documents']

    def approve_documents(self, request, queryset):
        queryset.update(verification_status='approved', rejection_reason=None)
        for doc in queryset:
            # Create notification for user
            Notification.objects.create(
                user=doc.user,
                title='KYC Document Approved',
                message=f'Your {doc.get_document_type_display()} has been approved.',
                type='system'
            )
        self.message_user(request, f"{queryset.count()} documents approved.")

    approve_documents.short_description = "Approve selected KYC documents"

    def reject_documents(self, request, queryset):
        rejection_reason = request.POST.get('rejection_reason', 'Document rejected by admin')
        queryset.update(verification_status='rejected', rejection_reason=rejection_reason)
        for doc in queryset:
            # Create notification for user
            Notification.objects.create(
                user=doc.user,
                title='KYC Document Rejected',
                message=f'Your {doc.get_document_type_display()} has been rejected. Reason: {rejection_reason}',
                type='system'
            )
        self.message_user(request, f"{queryset.count()} documents rejected.")

    reject_documents.short_description = "Reject selected KYC documents"

    def file_preview(self, obj):
        if obj.file:
            if obj.file.url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                return format_html('<img src="{}" width="100" />', obj.file.url)
            else:
                return format_html('<a href="{}" target="_blank">View File</a>', obj.file.url)
        return "No file"

    file_preview.short_description = 'Preview'


# ============ SAVED ADDRESS ADMIN ============
class SavedAddressAdmin(admin.ModelAdmin):
    list_display = ['address_id', 'user', 'address_label', 'city', 'state', 'postal_code']
    list_filter = ['state', 'city']
    search_fields = ['user__email', 'user__full_name', 'street_address', 'city', 'postal_code']
    raw_id_fields = ['user']


# ============ VEHICLE PHOTO INLINE ============
class VehiclePhotoInline(admin.TabularInline):
    model = VehiclePhoto
    extra = 1
    fields = ['side', 'photo', 'photo_preview']
    readonly_fields = ['photo_preview']

    def photo_preview(self, obj):
        if obj.photo:
            return format_html('<img src="{}" width="100" />', obj.photo.url)
        return "No photo"

    photo_preview.short_description = 'Preview'


# ============ VEHICLE SCHEDULE INLINE ============
class VehicleScheduleInline(admin.TabularInline):
    model = VehicleSchedule
    extra = 1
    fields = ['start_location', 'end_location', 'available_from', 'available_to', 'status']


# ============ VEHICLE ADMIN ============
class VehicleAdmin(admin.ModelAdmin):
    list_display = ['vehicle_id', 'registration_number', 'owner', 'vehicle_type', 'capacity_ton', 'verification_status',
                    'is_active', 'created_at']
    list_filter = ['vehicle_type', 'verification_status', 'is_active', 'created_at']
    search_fields = ['registration_number', 'owner__email', 'owner__full_name', 'manufacturer']
    raw_id_fields = ['owner']
    inlines = [VehiclePhotoInline, VehicleScheduleInline]

    actions = ['verify_vehicles', 'reject_vehicles']

    def verify_vehicles(self, request, queryset):
        queryset.update(verification_status='verified')
        for vehicle in queryset:
            # Create notification for owner
            Notification.objects.create(
                user=vehicle.owner,
                title='Vehicle Verified',
                message=f'Your vehicle {vehicle.registration_number} has been verified.',
                type='system'
            )
        self.message_user(request, f"{queryset.count()} vehicles verified.")

    verify_vehicles.short_description = "Verify selected vehicles"

    def reject_vehicles(self, request, queryset):
        queryset.update(verification_status='rejected')
        for vehicle in queryset:
            # Create notification for owner
            Notification.objects.create(
                user=vehicle.owner,
                title='Vehicle Rejected',
                message=f'Your vehicle {vehicle.registration_number} has been rejected. Please check and resubmit.',
                type='system'
            )
        self.message_user(request, f"{queryset.count()} vehicles rejected.")

    reject_vehicles.short_description = "Reject selected vehicles"


# ============ VEHICLE PHOTO ADMIN ============
class VehiclePhotoAdmin(admin.ModelAdmin):
    list_display = ['photo_id', 'vehicle', 'side', 'uploaded_at']
    list_filter = ['side', 'uploaded_at']
    search_fields = ['vehicle__registration_number']
    raw_id_fields = ['vehicle']

    def photo_preview(self, obj):
        if obj.photo:
            return format_html('<img src="{}" width="100" />', obj.photo.url)
        return "No photo"

    photo_preview.short_description = 'Preview'


# ============ VEHICLE SCHEDULE ADMIN ============
class VehicleScheduleAdmin(admin.ModelAdmin):
    list_display = ['schedule_id', 'vehicle', 'start_location', 'end_location', 'available_from', 'available_to',
                    'trip_type', 'status']
    list_filter = ['trip_type', 'status', 'available_from']
    search_fields = ['vehicle__registration_number', 'start_location', 'end_location']
    raw_id_fields = ['vehicle']
    date_hierarchy = 'available_from'


# ============ LOAD ADMIN ============
class LoadAdmin(admin.ModelAdmin):
    list_display = ['load_id', 'consignee', 'material_type', 'weight_kg', 'pickup_date', 'status', 'booking_type',
                    'created_at']
    list_filter = ['status', 'trip_mode', 'booking_type', 'is_fragile', 'created_at']
    search_fields = ['consignee__email', 'consignee__full_name', 'material_type', 'pickup_address', 'drop_address']
    raw_id_fields = ['consignee']
    date_hierarchy = 'pickup_date'

    fieldsets = (
        ('Basic Information', {
            'fields': ('consignee', 'material_type', 'weight_kg', 'required_vehicle_type')
        }),
        ('Pickup Details', {
            'fields': ('pickup_address', 'pickup_lat', 'pickup_lng', 'pickup_date')
        }),
        ('Drop Details', {
            'fields': ('drop_address', 'drop_lat', 'drop_lng')
        }),
        ('Additional Information', {
            'fields': ('is_fragile', 'special_instructions', 'trip_mode', 'booking_type', 'budget_price', 'status')
        }),
    )


# ============ BID ADMIN ============
class BidAdmin(admin.ModelAdmin):
    list_display = ['bid_id', 'load', 'transporter', 'vehicle', 'bid_amount', 'bid_status', 'created_at']
    list_filter = ['bid_status', 'created_at']
    search_fields = ['load__load_id', 'transporter__email', 'transporter__full_name']
    raw_id_fields = ['load', 'transporter', 'vehicle']

    actions = ['accept_bids', 'reject_bids']

    def accept_bids(self, request, queryset):
        for bid in queryset:
            if bid.bid_status == 'pending':
                bid.bid_status = 'accepted'
                bid.save()
                # Update load status
                load = bid.load
                load.status = 'assigned'
                load.save()
                # Reject other bids
                Bid.objects.filter(load=load, bid_status='pending').update(bid_status='rejected')
        self.message_user(request, f"{queryset.count()} bids accepted.")

    accept_bids.short_description = "Accept selected bids"

    def reject_bids(self, request, queryset):
        queryset.update(bid_status='rejected')
        self.message_user(request, f"{queryset.count()} bids rejected.")

    reject_bids.short_description = "Reject selected bids"


# ============ BOOKING ADMIN ============
class BookingAdmin(admin.ModelAdmin):
    list_display = ['booking_id', 'load', 'consignee', 'transporter', 'vehicle', 'booking_status', 'total_amount',
                    'created_at']
    list_filter = ['booking_status', 'created_at', 'completed_at']
    search_fields = ['load__load_id', 'consignee__email', 'transporter__email']
    raw_id_fields = ['load', 'consignee', 'transporter', 'vehicle', 'driver']
    readonly_fields = ['created_at', 'completed_at']

    fieldsets = (
        ('Booking Information', {
            'fields': ('load', 'consignee', 'transporter', 'vehicle', 'driver')
        }),
        ('Pricing', {
            'fields': ('agreed_price', 'tax_amount', 'total_amount')
        }),
        ('Status & OTP', {
            'fields': ('booking_status', 'pickup_otp', 'delivery_otp')
        }),
        ('Documents', {
            'fields': ('eway_bill_no', 'invoice', 'bilty')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'completed_at')
        }),
    )

    actions = ['mark_as_completed', 'mark_as_cancelled']

    def mark_as_completed(self, request, queryset):
        queryset.update(booking_status='completed', completed_at=timezone.now())
        self.message_user(request, f"{queryset.count()} bookings marked as completed.")

    mark_as_completed.short_description = "Mark selected bookings as completed"

    def mark_as_cancelled(self, request, queryset):
        queryset.update(booking_status='cancelled')
        self.message_user(request, f"{queryset.count()} bookings marked as cancelled.")

    mark_as_cancelled.short_description = "Mark selected bookings as cancelled"


# ============ SHIPMENT TRACKING ADMIN ============
class ShipmentTrackingAdmin(admin.ModelAdmin):
    list_display = ['tracking_id', 'booking', 'latitude', 'longitude', 'current_location_text', 'timestamp']
    list_filter = ['timestamp']
    search_fields = ['booking__booking_id', 'current_location_text']
    raw_id_fields = ['booking']
    readonly_fields = ['timestamp']


# ============ WALLET ADMIN ============
class WalletAdmin(admin.ModelAdmin):
    list_display = ['wallet_id', 'user', 'balance', 'currency', 'updated_at']
    list_filter = ['currency', 'updated_at']
    search_fields = ['user__email', 'user__full_name']
    raw_id_fields = ['user']
    readonly_fields = ['updated_at']


# ============ WALLET TRANSACTION ADMIN ============
class WalletTransactionAdmin(admin.ModelAdmin):
    list_display = ['transaction_id', 'wallet', 'amount', 'transaction_type', 'reference_type', 'reference_id',
                    'created_at']
    list_filter = ['transaction_type', 'reference_type', 'created_at']
    search_fields = ['wallet__user__email', 'description']
    raw_id_fields = ['wallet']
    readonly_fields = ['created_at']


# ============ PAYMENT ADMIN ============
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['payment_id', 'booking', 'payer', 'payee', 'amount', 'payment_gateway', 'payment_status',
                    'created_at']
    list_filter = ['payment_gateway', 'payment_status', 'created_at']
    search_fields = ['booking__booking_id', 'gateway_txn_id']
    raw_id_fields = ['booking', 'payer', 'payee']
    readonly_fields = ['created_at', 'released_at']

    actions = ['release_payments']

    def release_payments(self, request, queryset):
        queryset.update(payment_status='released_to_vendor', released_at=timezone.now())
        self.message_user(request, f"{queryset.count()} payments released.")

    release_payments.short_description = "Release selected payments"


# ============ RATING ADMIN ============
class RatingAdmin(admin.ModelAdmin):
    list_display = ['rating_id', 'booking', 'reviewer', 'reviewee', 'score', 'created_at']
    list_filter = ['score', 'created_at']
    search_fields = ['reviewer__email', 'reviewee__email', 'comment']
    raw_id_fields = ['booking', 'reviewer', 'reviewee']


# ============ DISPUTE ADMIN ============
class DisputeAdmin(admin.ModelAdmin):
    list_display = ['dispute_id', 'booking', 'raised_by', 'reason_category', 'status', 'created_at']
    list_filter = ['reason_category', 'status', 'created_at']
    search_fields = ['raised_by__email', 'description']
    raw_id_fields = ['booking', 'raised_by']

    actions = ['mark_investigating', 'mark_resolved']

    def mark_investigating(self, request, queryset):
        queryset.update(status='investigating')
        self.message_user(request, f"{queryset.count()} disputes marked as investigating.")

    mark_investigating.short_description = "Mark as investigating"

    def mark_resolved(self, request, queryset):
        queryset.update(status='resolved')
        self.message_user(request, f"{queryset.count()} disputes marked as resolved.")

    mark_resolved.short_description = "Mark as resolved"


# ============ NOTIFICATION ADMIN ============
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['notification_id', 'user', 'title', 'is_read', 'type', 'created_at']
    list_filter = ['is_read', 'type', 'created_at']
    search_fields = ['user__email', 'title', 'message']
    raw_id_fields = ['user']
    readonly_fields = ['created_at']


# ============ ADMIN LOG ADMIN ============
class AdminLogAdmin(admin.ModelAdmin):
    list_display = ['log_id', 'admin_user', 'action_type', 'target_id', 'created_at']
    list_filter = ['action_type', 'created_at']
    search_fields = ['admin_user__email', 'details']
    raw_id_fields = ['admin_user']
    readonly_fields = ['created_at']


# ============ REGISTER ALL MODELS WITH ADMIN ============
admin.site.register(User, UserAdmin)
admin.site.register(OTP, OTPAdmin)
admin.site.register(CorporateProfile, CorporateProfileAdmin)
admin.site.register(KYCDocument, KYCDocumentAdmin)
admin.site.register(SavedAddress, SavedAddressAdmin)
admin.site.register(Vehicle, VehicleAdmin)
admin.site.register(VehiclePhoto, VehiclePhotoAdmin)
admin.site.register(VehicleSchedule, VehicleScheduleAdmin)
admin.site.register(Load, LoadAdmin)
admin.site.register(Bid, BidAdmin)
admin.site.register(Booking, BookingAdmin)
admin.site.register(ShipmentTracking, ShipmentTrackingAdmin)
admin.site.register(Wallet, WalletAdmin)
admin.site.register(WalletTransaction, WalletTransactionAdmin)
admin.site.register(Payment, PaymentAdmin)
admin.site.register(Rating, RatingAdmin)
admin.site.register(Dispute, DisputeAdmin)
admin.site.register(Notification, NotificationAdmin)
admin.site.register(AdminLog, AdminLogAdmin)

# ============ CUSTOMIZE ADMIN SITE ============
admin.site.site_header = 'TempoLogi Administration'
admin.site.site_title = 'TempoLogi Admin'
admin.site.index_title = 'Dashboard'