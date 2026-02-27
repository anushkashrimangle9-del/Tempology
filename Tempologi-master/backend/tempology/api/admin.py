from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.db.models import Count, Sum, Avg
from django.utils import timezone
from django.urls import reverse
from django.db.models import Q
from datetime import timedelta
from .models import *

def safe_format_html(format_string, *args, **kwargs):
    """
    Safely call format_html with proper error handling
    """
    try:
        # Convert all args to strings to prevent type issues
        safe_args = [str(arg) if arg is not None else '' for arg in args]
        safe_kwargs = {k: str(v) if v is not None else '' for k, v in kwargs.items()}
        return format_html(format_string, *safe_args, **safe_kwargs)
    except Exception as e:
        # Return a safe fallback with error message for debugging
        return f"[Error formatting: {str(e)}]"

# ============ INLINE MODELS ============
class VehiclePhotoInline(admin.TabularInline):
    model = VehiclePhoto
    extra = 1
    fields = ['side', 'photo_url', 'photo_preview']
    readonly_fields = ['photo_preview']

    def photo_preview(self, obj):
        if obj.photo_url:
            try:
                return format_html('<img src="{}" width="100" height="100" style="object-fit: cover;" />',
                                   obj.photo_url.url)
            except:
                return "No Image"
        return "No Image"

    photo_preview.short_description = 'Preview'


class ExtraChargeInline(admin.TabularInline):
    model = ExtraCharge
    extra = 0
    fields = ['charge_type', 'description', 'amount', 'created_at']
    readonly_fields = ['created_at']


class PenaltyInline(admin.TabularInline):
    model = Penalty
    extra = 0
    fields = ['penalty_type', 'penalty_amount', 'status', 'created_at']
    readonly_fields = ['created_at']


class TripLocationInline(admin.TabularInline):
    model = TripLocation
    extra = 0
    fields = ['latitude', 'longitude', 'location_address', 'timestamp']
    readonly_fields = ['timestamp']


# ============ USER ADMIN ============
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = (
        'user_id', 'profile_image_thumb', 'full_name', 'email', 'phone_number',
        'role_colored', 'plan_type_colored', 'rating_stars', 'visibility_score_bar',
        'status_colored', 'is_verified', 'created_at'
    )
    list_filter = ('role', 'status', 'plan_type', 'is_verified', 'is_staff', 'is_active', 'created_at')
    search_fields = ('full_name', 'email', 'phone_number', 'user_id')
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'
    list_per_page = 25
    list_select_related = True

    fieldsets = (
        ('Personal Info', {
            'fields': ('profile_image_url', 'full_name', 'email', 'phone_number')
        }),
        ('Account Details', {
            'fields': ('role', 'plan_type', 'status', 'is_verified', 'password')
        }),
        ('Performance Metrics', {
            'fields': ('rating', 'total_trips', 'successful_deliveries',
                       'wrong_deliveries', 'late_deliveries', 'visibility_score', 'annual_turnover')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ('Important dates', {
            'fields': ('last_login', 'created_at', 'updated_at')
        }),
    )

    readonly_fields = ('created_at', 'updated_at', 'last_login', 'rating', 'visibility_score')
    actions = ['make_verified', 'make_unverified', 'make_active', 'make_inactive',
               'make_silver', 'make_gold', 'make_platinum', 'update_visibility']

    def profile_image_thumb(self, obj):
        try:
            if obj and obj.profile_image_url:
                try:
                    return safe_format_html('<img src="{}" width="40" height="40" style="border-radius: 50%;" />',
                                            obj.profile_image_url.url)
                except:
                    return safe_format_html(
                        '<div style="width:40px;height:40px;background:#ccc;border-radius:50%;display:flex;align-items:center;justify-content:center;">📷</div>')
        except:
            pass
        return safe_format_html(
            '<div style="width:40px;height:40px;background:#ccc;border-radius:50%;display:flex;align-items:center;justify-content:center;">📷</div>')

    profile_image_thumb.short_description = 'Photo'

    def role_colored(self, obj):
        colors = {
            'admin': 'red',
            'consignee': 'blue',
            'corporate': 'purple',
            'transporter': 'green',
            'truck_owner': 'orange',
            'driver': 'brown',
        }
        color = colors.get(obj.role, 'black')
        role_display = obj.get_role_display()
        return safe_format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, role_display
        )

    role_colored.short_description = 'Role'

    def plan_type_colored(self, obj):
        colors = {
            'platinum': 'purple',
            'gold': 'goldenrod',
            'silver': 'silver',
        }
        color = colors.get(obj.plan_type, 'black')
        plan_display = obj.get_plan_type_display()
        return safe_format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, plan_display
        )

    plan_type_colored.short_description = 'Plan'

    def status_colored(self, obj):
        colors = {
            'active': 'green',
            'inactive': 'gray',
            'suspended': 'red',
            'banned': 'darkred',
        }
        color = colors.get(obj.status, 'black')
        status_display = obj.get_status_display()
        return safe_format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, status_display
        )

    status_colored.short_description = 'Status'

    def rating_stars(self, obj):
        try:
            rating = float(obj.rating) if obj.rating is not None else 0
        except (TypeError, ValueError):
            rating = 0

        full_stars = int(rating)
        half_star = 1 if rating - full_stars >= 0.5 else 0
        empty_stars = 5 - full_stars - half_star

        stars = '★' * full_stars
        if half_star:
            stars += '½'
        stars += '☆' * empty_stars

        return safe_format_html('<span style="color: gold;">{}</span> <span style="color: gray;">({})</span>',
                                stars, str(rating))

    rating_stars.short_description = 'Rating'

    def visibility_score_bar(self, obj):
        try:
            score = float(obj.visibility_score) if obj.visibility_score is not None else 0
        except (TypeError, ValueError):
            score = 0
        color = 'green' if score >= 80 else 'orange' if score >= 50 else 'red'
        return safe_format_html(
            '<div style="width:100px;background:#eee;"><div style="width:{}%;background:{};height:10px;"></div></div> {}%',
            str(score), color, str(score)
        )

    visibility_score_bar.short_description = 'Visibility'

    def make_verified(self, request, queryset):
        queryset.update(is_verified=True)
        self.message_user(request, f"{queryset.count()} users marked as verified.")

    make_verified.short_description = "Mark selected as verified"

    def make_unverified(self, request, queryset):
        queryset.update(is_verified=False)
        self.message_user(request, f"{queryset.count()} users marked as unverified.")

    make_unverified.short_description = "Mark selected as unverified"

    def make_active(self, request, queryset):
        queryset.update(status='active', is_active=True)
        self.message_user(request, f"{queryset.count()} users activated.")

    make_active.short_description = "Activate selected users"

    def make_inactive(self, request, queryset):
        queryset.update(status='inactive', is_active=False)
        self.message_user(request, f"{queryset.count()} users deactivated.")

    make_inactive.short_description = "Deactivate selected users"

    def make_silver(self, request, queryset):
        queryset.update(plan_type='silver')
        self.message_user(request, f"{queryset.count()} users set to Silver plan.")

    make_silver.short_description = "Set Silver plan"

    def make_gold(self, request, queryset):
        queryset.update(plan_type='gold')
        self.message_user(request, f"{queryset.count()} users set to Gold plan.")

    make_gold.short_description = "Set Gold plan"

    def make_platinum(self, request, queryset):
        queryset.update(plan_type='platinum')
        self.message_user(request, f"{queryset.count()} users set to Platinum plan.")

    make_platinum.short_description = "Set Platinum plan"

    def update_visibility(self, request, queryset):
        for user in queryset:
            user.update_visibility_score()
        self.message_user(request, f"Visibility scores updated for {queryset.count()} users.")

    update_visibility.short_description = "Update visibility scores"


# ============ OTP ADMIN ============
@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = (
        'id_short', 'email', 'phone_number', 'otp', 'otp_type_colored',
        'is_used', 'is_verified', 'expires_at_colored', 'created_at'
    )
    list_filter = ('otp_type', 'is_used', 'is_verified', 'created_at')
    search_fields = ('email', 'phone_number', 'otp')
    ordering = ('-created_at',)
    readonly_fields = ('id', 'created_at')

    def id_short(self, obj):
        return str(obj.id)[:8] if obj and obj.id else ""

    id_short.short_description = 'ID'

    def otp_type_colored(self, obj):
        colors = {
            'email_registration': 'blue',
            'phone_registration': 'green',
            'password_reset': 'orange',
        }
        color = colors.get(obj.otp_type, 'black')
        otp_display = obj.get_otp_type_display()
        return safe_format_html(
            '<span style="color: {};">{}</span>',
            color, otp_display
        )

    otp_type_colored.short_description = 'OTP Type'

    def expires_at_colored(self, obj):
        if obj.is_expired():
            return safe_format_html('<span style="color: red;">{} (Expired)</span>',
                                    obj.expires_at.strftime('%Y-%m-%d %H:%M'))
        return safe_format_html('<span style="color: green;">{}</span>',
                                obj.expires_at.strftime('%Y-%m-%d %H:%M'))

    expires_at_colored.short_description = 'Expires At'

# ============ CORPORATE PROFILE ADMIN ============
@admin.register(CorporateProfile)
class CorporateProfileAdmin(admin.ModelAdmin):
    list_display = (
        'corporate_id', 'user_link', 'company_name', 'gst_number',
        'credit_limit_colored', 'contract_period', 'is_contract_active'
    )
    list_filter = ('contract_start_date', 'contract_end_date')
    search_fields = ('company_name', 'gst_number', 'user__full_name', 'user__email')
    raw_id_fields = ('user',)

    def user_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.user.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.user.full_name)

    user_link.short_description = 'User'

    def credit_limit_colored(self, obj):
        if obj.credit_limit > 100000:
            color = 'green'
        elif obj.credit_limit > 50000:
            color = 'orange'
        else:
            color = 'red'
        return format_html('<span style="color: {}; font-weight: bold;">₹{}</span>',
                           color, str(obj.credit_limit))

    credit_limit_colored.short_description = 'Credit Limit'

    def contract_period(self, obj):
        if obj.contract_start_date and obj.contract_end_date:
            return f"{obj.contract_start_date} to {obj.contract_end_date}"
        return "Not set"

    contract_period.short_description = 'Contract Period'

    def is_contract_active(self, obj):
        today = timezone.now().date()
        if obj.contract_start_date and obj.contract_end_date:
            if obj.contract_start_date <= today <= obj.contract_end_date:
                return format_html('<span style="color: green;">✓ Active</span>')
        return format_html('<span style="color: gray;">✗ Inactive</span>')

    is_contract_active.short_description = 'Contract Status'


# ============ VEHICLE CATEGORY ADMIN ============
@admin.register(VehicleCategory)
class VehicleCategoryAdmin(admin.ModelAdmin):
    list_display = (
        'category_id', 'name', 'vehicle_type_colored', 'capacity_ton', 'length_ft',
        'base_rate_per_km', 'base_charge', 'sample_rates', 'is_active_colored'
    )
    list_filter = ('vehicle_type', 'is_active')
    search_fields = ('name',)
    actions = ['duplicate_category', 'enable_categories', 'disable_categories']

    def vehicle_type_colored(self, obj):
        colors = {
            'mini_truck': 'blue',
            'tempo': 'green',
            'container': 'purple',
            'trailer': 'orange',
            'open_body': 'brown',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.vehicle_type, 'black'),
            obj.get_vehicle_type_display()
        )

    vehicle_type_colored.short_description = 'Vehicle Type'

    def is_active_colored(self, obj):
        if obj.is_active:
            return format_html('<span style="color: green;">✓ Active</span>')
        return format_html('<span style="color: red;">✗ Inactive</span>')

    is_active_colored.short_description = 'Active'

    def sample_rates(self, obj):
        html = []
        if obj.sample_rate_10ton:
            html.append(f'10T: ₹{obj.sample_rate_10ton}')
        if obj.sample_rate_16ton:
            html.append(f'16T: ₹{obj.sample_rate_16ton}')
        if obj.sample_rate_22ft:
            html.append(f'22ft: ₹{obj.sample_rate_22ft}')
        return format_html('<br>'.join(html) if html else '-')

    sample_rates.short_description = 'Sample Rates'

    def duplicate_category(self, request, queryset):
        for category in queryset:
            category.pk = None
            category.name = f"{category.name} (Copy)"
            category.save()
        self.message_user(request, f"{queryset.count()} categories duplicated.")

    duplicate_category.short_description = "Duplicate selected categories"

    def enable_categories(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} categories enabled.")

    enable_categories.short_description = "Enable selected categories"

    def disable_categories(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} categories disabled.")

    disable_categories.short_description = "Disable selected categories"


# ============ PRICING SLAB ADMIN ============
@admin.register(PricingSlab)
class PricingSlabAdmin(admin.ModelAdmin):
    list_display = (
        'slab_id', 'vehicle_category_link', 'slab_type_colored', 'distance_range',
        'weight_range', 'rate_per_km', 'rate_per_ton_km', 'is_base_slab',
        'peak_multiplier', 'is_active_colored'
    )
    list_filter = ('vehicle_category', 'slab_type', 'is_base_slab', 'is_active')
    search_fields = ('vehicle_category__name',)
    list_editable = ('rate_per_km', 'peak_multiplier')
    actions = ['enable_slabs', 'disable_slabs']

    def vehicle_category_link(self, obj):
        link = reverse('admin:api_vehiclecategory_change', args=[obj.vehicle_category.category_id])
        return format_html('<a href="{}">{}</a>', link, obj.vehicle_category.name)

    vehicle_category_link.short_description = 'Vehicle Category'

    def slab_type_colored(self, obj):
        colors = {
            'distance': 'blue',
            'weight': 'green',
            'combined': 'purple',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.slab_type, 'black'),
            obj.get_slab_type_display()
        )

    slab_type_colored.short_description = 'Slab Type'

    def distance_range(self, obj):
        if obj.max_distance:
            return f"{obj.min_distance} - {obj.max_distance} km"
        return f"{obj.min_distance}+ km"

    distance_range.short_description = 'Distance Range'

    def weight_range(self, obj):
        if obj.max_weight_ton:
            return f"{obj.min_weight_ton} - {obj.max_weight_ton} ton"
        return f"{obj.min_weight_ton}+ ton"

    weight_range.short_description = 'Weight Range'

    def is_active_colored(self, obj):
        if obj.is_active:
            return format_html('<span style="color: green;">✓ Active</span>')
        return format_html('<span style="color: red;">✗ Inactive</span>')

    is_active_colored.short_description = 'Active'

    def enable_slabs(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} pricing slabs enabled.")

    enable_slabs.short_description = "Enable selected slabs"

    def disable_slabs(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} pricing slabs disabled.")

    disable_slabs.short_description = "Disable selected slabs"


# ============ VEHICLE ADMIN ============
@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = (
        'vehicle_id', 'registration_number', 'vehicle_type_colored',
        'owner_link', 'capacity_ton', 'verification_status_colored',
        'is_active', 'photo_count', 'created_at'
    )
    list_filter = ('vehicle_type', 'verification_status', 'is_active', 'created_at')
    search_fields = ('registration_number', 'manufacturer', 'owner__full_name')
    raw_id_fields = ('owner',)
    readonly_fields = ('created_at',)
    inlines = [VehiclePhotoInline]
    actions = ['verify_vehicles', 'reject_vehicles', 'mark_active', 'mark_inactive']

    def owner_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.owner.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.owner.full_name)

    owner_link.short_description = 'Owner'

    def vehicle_type_colored(self, obj):
        colors = {
            'mini_truck': 'blue',
            'tempo': 'green',
            'container': 'purple',
            'trailer': 'orange',
            'open_body': 'brown',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.vehicle_type, 'black'),
            obj.get_vehicle_type_display()
        )

    vehicle_type_colored.short_description = 'Type'

    def verification_status_colored(self, obj):
        colors = {
            'pending': 'orange',
            'verified': 'green',
            'rejected': 'red',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.verification_status, 'black'),
            obj.get_verification_status_display()
        )

    verification_status_colored.short_description = 'Status'

    def photo_count(self, obj):
        count = obj.photos.count()
        return format_html('<span style="font-weight: bold; color: {};">{}</span>',
                           'green' if count > 0 else 'gray', str(count))

    photo_count.short_description = 'Photos'

    def verify_vehicles(self, request, queryset):
        queryset.update(verification_status='verified')
        self.message_user(request, f"{queryset.count()} vehicles verified.")

    verify_vehicles.short_description = "Verify selected vehicles"

    def reject_vehicles(self, request, queryset):
        queryset.update(verification_status='rejected')
        self.message_user(request, f"{queryset.count()} vehicles rejected.")

    reject_vehicles.short_description = "Reject selected vehicles"

    def mark_active(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} vehicles marked active.")

    mark_active.short_description = "Mark as active"

    def mark_inactive(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} vehicles marked inactive.")

    mark_inactive.short_description = "Mark as inactive"


# ============ VEHICLE PHOTO ADMIN ============
@admin.register(VehiclePhoto)
class VehiclePhotoAdmin(admin.ModelAdmin):
    list_display = ('photo_id', 'vehicle_link', 'side', 'photo_thumbnail', 'uploaded_at')
    list_filter = ('side', 'uploaded_at')
    search_fields = ('vehicle__registration_number',)
    raw_id_fields = ('vehicle',)
    readonly_fields = ('uploaded_at', 'photo_preview')

    def vehicle_link(self, obj):
        link = reverse('admin:api_vehicle_change', args=[obj.vehicle.vehicle_id])
        return format_html('<a href="{}">{}</a>', link, obj.vehicle.registration_number)

    vehicle_link.short_description = 'Vehicle'

    def photo_thumbnail(self, obj):
        if obj.photo_url:
            try:
                return format_html('<img src="{}" width="50" height="50" style="object-fit: cover;" />',
                                   obj.photo_url.url)
            except:
                return "No Image"
        return "No Image"

    photo_thumbnail.short_description = 'Thumbnail'

    def photo_preview(self, obj):
        if obj.photo_url:
            try:
                return format_html('<img src="{}" width="300" style="object-fit: contain;" />',
                                   obj.photo_url.url)
            except:
                return "No Image"
        return "No Image"

    photo_preview.short_description = 'Preview'


# ============ VEHICLE SCHEDULE ADMIN ============
@admin.register(VehicleSchedule)
class VehicleScheduleAdmin(admin.ModelAdmin):
    list_display = (
        'schedule_id', 'vehicle_link', 'trip_type_colored', 'route',
        'available_period', 'available_capacity', 'status_colored'
    )
    list_filter = ('trip_type', 'status', 'available_from')
    search_fields = ('start_location', 'end_location', 'vehicle__registration_number')
    raw_id_fields = ('vehicle',)

    def vehicle_link(self, obj):
        link = reverse('admin:api_vehicle_change', args=[obj.vehicle.vehicle_id])
        return format_html('<a href="{}">{}</a>', link, obj.vehicle.registration_number)

    vehicle_link.short_description = 'Vehicle'

    def trip_type_colored(self, obj):
        colors = {
            'one_way': 'blue',
            'return': 'green',
            'tempopool': 'purple',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.trip_type, 'black'),
            obj.get_trip_type_display()
        )

    trip_type_colored.short_description = 'Trip Type'

    def route(self, obj):
        start = obj.start_location[:20] + '...' if len(obj.start_location) > 20 else obj.start_location
        end = obj.end_location[:20] + '...' if len(obj.end_location) > 20 else obj.end_location
        return f"{start} → {end}"

    route.short_description = 'Route'

    def available_period(self, obj):
        from_dt = obj.available_from.strftime('%d %b %H:%M')
        to_dt = obj.available_to.strftime('%d %b %H:%M')
        return f"{from_dt} - {to_dt}"

    available_period.short_description = 'Available Period'

    def available_capacity(self, obj):
        if obj.available_capacity_ton:
            return f"{obj.available_capacity_ton} tons"
        return "Full"

    available_capacity.short_description = 'Available Capacity'

    def status_colored(self, obj):
        colors = {
            'active': 'green',
            'booked': 'orange',
            'expired': 'red',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.get_status_display()
        )

    status_colored.short_description = 'Status'


# ============ LOAD ADMIN ============
@admin.register(Load)
class LoadAdmin(admin.ModelAdmin):
    list_display = (
        'load_id', 'consignee_link', 'material_type', 'weight_kg',
        'route_summary', 'distance_km', 'budget_price_colored', 'status_colored',
        'pickup_date', 'requests_count'
    )
    list_filter = ('status', 'trip_mode', 'booking_type', 'is_fragile', 'is_deliverable', 'created_at')
    search_fields = ('material_type', 'pickup_address', 'drop_address', 'consignee__full_name')
    raw_id_fields = ('consignee', 'required_vehicle_category')
    readonly_fields = ('created_at', 'updated_at', 'distance_km', 'price_breakdown')
    actions = ['mark_open', 'mark_assigned', 'mark_delivered', 'mark_cancelled',
               'mark_deliverable', 'mark_not_deliverable']

    def consignee_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.consignee.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.consignee.full_name)

    consignee_link.short_description = 'Consignee'

    def route_summary(self, obj):
        pickup = obj.pickup_address[:20] + '...' if len(obj.pickup_address) > 20 else obj.pickup_address
        drop = obj.drop_address[:20] + '...' if len(obj.drop_address) > 20 else obj.drop_address
        return f"{pickup} → {drop}"

    route_summary.short_description = 'Route'

    def budget_price_colored(self, obj):
        if obj.budget_price:
            return format_html('<span style="color: green; font-weight: bold;">₹{}</span>', str(obj.budget_price))
        return "-"

    budget_price_colored.short_description = 'Budget Price'

    def status_colored(self, obj):
        colors = {
            'open': 'green',
            'assigned': 'blue',
            'in_transit': 'orange',
            'delivered': 'purple',
            'cancelled': 'red',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.get_status_display()
        )

    status_colored.short_description = 'Status'

    def requests_count(self, obj):
        count = obj.requests.count()
        if count > 0:
            link = reverse('admin:api_loadrequest_changelist') + f'?load__load_id={obj.load_id}'
            return format_html('<a href="{}" style="color: blue; font-weight: bold;">{}</a>', link, str(count))
        return str(count)

    requests_count.short_description = 'Requests'

    def mark_open(self, request, queryset):
        queryset.update(status='open')
        self.message_user(request, f"{queryset.count()} loads marked as open.")

    mark_open.short_description = "Mark as open"

    def mark_assigned(self, request, queryset):
        queryset.update(status='assigned')
        self.message_user(request, f"{queryset.count()} loads marked as assigned.")

    mark_assigned.short_description = "Mark as assigned"

    def mark_delivered(self, request, queryset):
        queryset.update(status='delivered')
        self.message_user(request, f"{queryset.count()} loads marked as delivered.")

    mark_delivered.short_description = "Mark as delivered"

    def mark_cancelled(self, request, queryset):
        queryset.update(status='cancelled')
        self.message_user(request, f"{queryset.count()} loads marked as cancelled.")

    mark_cancelled.short_description = "Mark as cancelled"

    def mark_deliverable(self, request, queryset):
        queryset.update(is_deliverable=True)
        self.message_user(request, f"{queryset.count()} loads marked as deliverable.")

    mark_deliverable.short_description = "Mark as deliverable"

    def mark_not_deliverable(self, request, queryset):
        queryset.update(is_deliverable=False)
        self.message_user(request, f"{queryset.count()} loads marked as not deliverable.")

    mark_not_deliverable.short_description = "Mark as not deliverable"


# ============ LOAD REQUEST ADMIN ============
@admin.register(LoadRequest)
class LoadRequestAdmin(admin.ModelAdmin):
    list_display = (
        'request_id', 'load_link', 'requester_link', 'vehicle_link',
        'total_price_colored', 'status_colored', 'expires_at_colored', 'created_at'
    )
    list_filter = ('status', 'created_at')
    search_fields = ('load__load_id', 'requester__full_name', 'message')
    raw_id_fields = ('load', 'requester', 'vehicle')
    readonly_fields = ('distance_km', 'base_price', 'weight_factor', 'traffic_multiplier',
                       'fuel_surcharge', 'total_price', 'created_at')
    actions = ['accept_requests', 'reject_requests']

    def load_link(self, obj):
        link = reverse('admin:api_load_change', args=[obj.load.load_id])
        return format_html('<a href="{}">Load #{}</a>', link, str(obj.load.load_id))

    load_link.short_description = 'Load'

    def requester_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.requester.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.requester.full_name)

    requester_link.short_description = 'Requester'

    def vehicle_link(self, obj):
        link = reverse('admin:api_vehicle_change', args=[obj.vehicle.vehicle_id])
        return format_html('<a href="{}">{}</a>', link, obj.vehicle.registration_number)

    vehicle_link.short_description = 'Vehicle'

    def total_price_colored(self, obj):
        return format_html('<span style="color: green; font-weight: bold;">₹{}</span>', str(obj.total_price))

    total_price_colored.short_description = 'Total Price'

    def status_colored(self, obj):
        colors = {
            'pending': 'orange',
            'accepted': 'green',
            'rejected': 'red',
            'withdrawn': 'gray',
            'expired': 'gray',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.get_status_display()
        )

    status_colored.short_description = 'Status'

    def expires_at_colored(self, obj):
        if obj.expires_at < timezone.now():
            return format_html('<span style="color: red;">{} (Expired)</span>',
                               obj.expires_at.strftime('%Y-%m-%d %H:%M'))
        return format_html('<span style="color: green;">{}</span>',
                           obj.expires_at.strftime('%Y-%m-%d %H:%M'))

    expires_at_colored.short_description = 'Expires At'

    def accept_requests(self, request, queryset):
        updated = queryset.update(status='accepted', responded_at=timezone.now())
        self.message_user(request, f"{updated} requests accepted.")

    accept_requests.short_description = "Accept selected requests"

    def reject_requests(self, request, queryset):
        updated = queryset.update(status='rejected', responded_at=timezone.now())
        self.message_user(request, f"{updated} requests rejected.")

    reject_requests.short_description = "Reject selected requests"


# ============ TRIP ADMIN ============
@admin.register(Trip)
class TripAdmin(admin.ModelAdmin):
    list_display = (
        'trip_id', 'vehicle_link', 'driver_link', 'route_short', 'status_colored',
        'delay_minutes_colored', 'is_halted', 'available_capacity', 'estimated_delivery'
    )
    list_filter = ('status', 'trip_type', 'is_halted', 'is_return_trip_available', 'created_at')
    search_fields = ('from_location', 'destination', 'vehicle__registration_number', 'driver__full_name')
    raw_id_fields = ('vehicle', 'driver', 'owner', 'booking')
    readonly_fields = ('created_at', 'updated_at', 'location_history')
    inlines = [TripLocationInline]
    actions = ['mark_delayed', 'mark_completed', 'mark_in_transit', 'recalculate_delays']

    def vehicle_link(self, obj):
        link = reverse('admin:api_vehicle_change', args=[obj.vehicle.vehicle_id])
        return format_html('<a href="{}">{}</a>', link, obj.vehicle.registration_number)

    vehicle_link.short_description = 'Vehicle'

    def driver_link(self, obj):
        if obj.driver:
            link = reverse('admin:api_user_change', args=[obj.driver.user_id])
            return format_html('<a href="{}">{}</a>', link, obj.driver.full_name)
        return "-"

    driver_link.short_description = 'Driver'

    def route_short(self, obj):
        from_loc = obj.from_location[:15] + '...' if len(obj.from_location) > 15 else obj.from_location
        to_loc = obj.destination[:15] + '...' if len(obj.destination) > 15 else obj.destination
        return f"{from_loc} → {to_loc}"

    route_short.short_description = 'Route'

    def status_colored(self, obj):
        colors = {
            'scheduled': 'blue',
            'confirmed': 'green',
            'boarding': 'orange',
            'in_transit': 'purple',
            'halted': 'red',
            'delivered': 'darkgreen',
            'cancelled': 'gray',
            'delayed': 'darkred',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.get_status_display()
        )

    status_colored.short_description = 'Status'

    def delay_minutes_colored(self, obj):
        if obj.delay_minutes > 0:
            color = 'red' if obj.delay_minutes > 120 else 'orange'
            return format_html('<span style="color: {}; font-weight: bold;">{} min</span>',
                               color, str(obj.delay_minutes))
        return "-"

    delay_minutes_colored.short_description = 'Delay'

    def available_capacity(self, obj):
        return f"{obj.available_capacity_kg} kg"

    available_capacity.short_description = 'Available'

    def estimated_delivery(self, obj):
        return obj.estimated_delivery_time.strftime('%d %b %H:%M') if obj.estimated_delivery_time else "-"

    estimated_delivery.short_description = 'Est. Delivery'

    def mark_delayed(self, request, queryset):
        queryset.update(status='delayed')
        self.message_user(request, f"{queryset.count()} trips marked as delayed.")

    mark_delayed.short_description = "Mark as delayed"

    def mark_completed(self, request, queryset):
        queryset.update(status='delivered', actual_delivery_time=timezone.now())
        self.message_user(request, f"{queryset.count()} trips marked as completed.")

    mark_completed.short_description = "Mark as completed"

    def mark_in_transit(self, request, queryset):
        queryset.update(status='in_transit')
        self.message_user(request, f"{queryset.count()} trips marked as in transit.")

    mark_in_transit.short_description = "Mark as in transit"

    def recalculate_delays(self, request, queryset):
        for trip in queryset:
            trip.calculate_delay()
        self.message_user(request, f"Delays recalculated for {queryset.count()} trips.")

    recalculate_delays.short_description = "Recalculate delays"


# ============ TRIP LOCATION ADMIN ============
@admin.register(TripLocation)
class TripLocationAdmin(admin.ModelAdmin):
    list_display = ('location_id', 'trip_link', 'coordinates', 'location_address', 'timestamp')
    list_filter = ('timestamp',)
    search_fields = ('trip__trip_id', 'location_address')
    raw_id_fields = ('trip',)

    def trip_link(self, obj):
        link = reverse('admin:api_trip_change', args=[obj.trip.trip_id])
        return format_html('<a href="{}">Trip #{}</a>', link, str(obj.trip.trip_id))

    trip_link.short_description = 'Trip'

    def coordinates(self, obj):
        return f"{obj.latitude}, {obj.longitude}"

    coordinates.short_description = 'Coordinates'


# ============ RETURN TRIP OFFER ADMIN ============
@admin.register(ReturnTripOffer)
class ReturnTripOfferAdmin(admin.ModelAdmin):
    list_display = ('offer_id', 'trip_link', 'route', 'available_space', 'offered_price',
                    'is_active', 'is_booked', 'created_at')
    list_filter = ('is_active', 'is_booked', 'created_at')
    search_fields = ('from_location', 'to_location')
    raw_id_fields = ('original_trip',)

    def trip_link(self, obj):
        link = reverse('admin:api_trip_change', args=[obj.original_trip.trip_id])
        return format_html('<a href="{}">Trip #{}</a>', link, str(obj.original_trip.trip_id))

    trip_link.short_description = 'Original Trip'

    def route(self, obj):
        return f"{obj.from_location[:20]} → {obj.to_location[:20]}"

    route.short_description = 'Route'

    def available_space(self, obj):
        return f"{obj.available_space_kg} kg"

    available_space.short_description = 'Space'


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = (
        'booking_id', 'load_link', 'consignee_link', 'transporter_link',
        'vehicle_link', 'total_amount_colored', 'booking_status', 'status_colored',
        'delivery_status', 'created_at'
    )
    list_filter = ('booking_status', 'created_at')
    search_fields = ('booking_id', 'consignee__full_name', 'transporter__full_name')
    readonly_fields = ('booking_id', 'created_at', 'completed_at', 'updated_at')  # Added booking_id here
    raw_id_fields = ('load', 'consignee', 'transporter', 'vehicle', 'driver')
    # inlines = [ExtraChargeInline, PenaltyInline]  # Make sure these are defined
    actions = ['mark_confirmed', 'mark_completed', 'mark_cancelled', 'regenerate_otps']

    # Add booking_status to list_editable
    list_editable = ('booking_status',)

    # Add list_select_related for performance
    list_select_related = ('load', 'consignee', 'transporter', 'vehicle', 'driver')

    # Add radio fields for status choices
    radio_fields = {'booking_status': admin.HORIZONTAL}

    # CORRECTED FIELDSETS - Removed booking_id from fields
    fieldsets = (
        ('Booking Information', {
            'fields': ('load', 'consignee', 'transporter', 'vehicle', 'driver')
        }),
        ('Financial Details', {
            'fields': ('agreed_price', 'tax_amount', 'total_amount')
        }),
        ('OTP Verification', {
            'fields': ('pickup_otp', 'delivery_otp'),
            'classes': ('wide',)
        }),
        ('Status & Timeline', {
            'fields': ('booking_status', 'delivery_time_commitment', 'actual_delivery_time',
                       'created_at', 'completed_at', 'updated_at')
        }),
        ('Documents', {
            'fields': ('eway_bill_no', 'invoice_url', 'bilty_url'),
            'classes': ('wide',)
        }),
    )

    def get_readonly_fields(self, request, obj=None):
        """Return readonly fields based on whether we're adding or editing"""
        readonly_fields = list(self.readonly_fields)

        if obj:  # Editing an existing object
            # These fields should be readonly when editing
            readonly_fields.extend(['load', 'consignee', 'transporter', 'vehicle'])
        else:  # Adding a new object
            # For new objects, we want these fields to be editable
            pass

        return readonly_fields

    def load_link(self, obj):
        if obj and obj.load:
            link = reverse('admin:api_load_change', args=[obj.load.load_id])
            return format_html('<a href="{}">Load #{}</a>', link, obj.load.load_id)
        return "-"

    load_link.short_description = 'Load'
    load_link.admin_order_field = 'load'

    def consignee_link(self, obj):
        if obj and obj.consignee:
            link = reverse('admin:api_user_change', args=[obj.consignee.user_id])
            return format_html('<a href="{}">{}</a>', link, obj.consignee.full_name)
        return "-"

    consignee_link.short_description = 'Consignee'
    consignee_link.admin_order_field = 'consignee'

    def transporter_link(self, obj):
        if obj and obj.transporter:
            link = reverse('admin:api_user_change', args=[obj.transporter.user_id])
            return format_html('<a href="{}">{}</a>', link, obj.transporter.full_name)
        return "-"

    transporter_link.short_description = 'Transporter'
    transporter_link.admin_order_field = 'transporter'

    def vehicle_link(self, obj):
        if obj and obj.vehicle:
            link = reverse('admin:api_vehicle_change', args=[obj.vehicle.vehicle_id])
            return format_html('<a href="{}">{}</a>', link, obj.vehicle.registration_number)
        return "-"

    vehicle_link.short_description = 'Vehicle'
    vehicle_link.admin_order_field = 'vehicle'

    def total_amount_colored(self, obj):
        if obj and obj.total_amount:
            return format_html(
                '<span style="color: green; font-weight: bold;">₹{}</span>',
                obj.total_amount
            )
        return "-"

    total_amount_colored.short_description = 'Total'
    total_amount_colored.admin_order_field = 'total_amount'

    def status_colored(self, obj):
        if obj:
            colors = {
                'confirmed': '#0d6efd',  # blue
                'driver_assigned': '#198754',  # green
                'at_pickup': '#fd7e14',  # orange
                'loaded': '#6f42c1',  # purple
                'in_transit': '#795548',  # brown
                'at_delivery': '#fd7e14',  # darkorange
                'completed': '#198754',  # darkgreen
                'cancelled': '#6c757d',  # gray
                'delayed': '#dc3545',  # red
            }
            color = colors.get(obj.booking_status, '#212529')
            status_display = obj.get_booking_status_display()
            return format_html(
                '<span style="color: {}; font-weight: bold;">{}</span>',
                color, status_display
            )
        return "-"

    status_colored.short_description = 'Status'
    status_colored.admin_order_field = 'booking_status'

    def delivery_status(self, obj):
        if obj and obj.delivery_time_commitment:
            if obj.actual_delivery_time:
                if obj.actual_delivery_time <= obj.delivery_time_commitment:
                    return format_html('<span style="color: #198754;">On Time</span>')
                else:
                    # Calculate delay
                    delay = (obj.actual_delivery_time - obj.delivery_time_commitment).total_seconds() / 3600
                    return format_html(
                        '<span style="color: #dc3545;">Delayed ({}h)</span>',
                        round(delay, 1)
                    )
            else:
                if timezone.now() > obj.delivery_time_commitment:
                    # Calculate overdue
                    overdue = (timezone.now() - obj.delivery_time_commitment).total_seconds() / 3600
                    return format_html(
                        '<span style="color: #ffc107;">Overdue ({}h)</span>',
                        round(overdue, 1)
                    )
                else:
                    # Time remaining
                    remaining = (obj.delivery_time_commitment - timezone.now()).total_seconds() / 3600
                    return format_html(
                        '<span style="color: #0d6efd;">{}h left</span>',
                        round(remaining, 1)
                    )
        return format_html('<span style="color: #6c757d;">-</span>')

    delivery_status.short_description = 'Delivery Status'

    def mark_confirmed(self, request, queryset):
        updated = queryset.update(booking_status='confirmed')
        self.message_user(request, f"{updated} bookings confirmed.")

    mark_confirmed.short_description = "Mark as confirmed"

    def mark_completed(self, request, queryset):
        updated = queryset.update(
            booking_status='completed',
            completed_at=timezone.now(),
            actual_delivery_time=timezone.now()
        )
        self.message_user(request, f"{updated} bookings completed.")

    mark_completed.short_description = "Mark as completed"

    def mark_cancelled(self, request, queryset):
        updated = queryset.update(booking_status='cancelled')
        self.message_user(request, f"{updated} bookings cancelled.")

    mark_cancelled.short_description = "Mark as cancelled"

    def regenerate_otps(self, request, queryset):
        import random
        count = 0
        for booking in queryset:
            booking.pickup_otp = str(random.randint(100000, 999999))
            booking.delivery_otp = str(random.randint(100000, 999999))
            booking.save()
            count += 1
        self.message_user(request, f"OTPs regenerated for {count} bookings.")

    regenerate_otps.short_description = "Regenerate OTPs"
# ============ EXTRA CHARGE ADMIN ============
@admin.register(ExtraCharge)
class ExtraChargeAdmin(admin.ModelAdmin):
    list_display = ('charge_id', 'booking_link', 'charge_type_colored', 'description',
                    'amount_colored', 'created_by_name', 'created_at')
    list_filter = ('charge_type', 'created_at')
    search_fields = ('booking__booking_id', 'description')
    raw_id_fields = ('booking', 'created_by')

    def booking_link(self, obj):
        link = reverse('admin:api_booking_change', args=[obj.booking.booking_id])
        return format_html('<a href="{}">Booking #{}</a>', link, str(obj.booking.booking_id))

    booking_link.short_description = 'Booking'

    def charge_type_colored(self, obj):
        colors = {
            'hamali': 'brown',
            'loading': 'blue',
            'unloading': 'blue',
            'handling': 'purple',
            'haulting': 'orange',
            'local_delivery': 'green',
            'waiting': 'red',
            'penalty': 'darkred',
            'other': 'gray',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.charge_type, 'black'),
            obj.get_charge_type_display()
        )

    charge_type_colored.short_description = 'Type'

    def amount_colored(self, obj):
        return format_html('<span style="color: green;">₹{}</span>', str(obj.amount))

    amount_colored.short_description = 'Amount'

    def created_by_name(self, obj):
        return obj.created_by.full_name if obj.created_by else "-"

    created_by_name.short_description = 'Created By'


# ============ PENALTY ADMIN ============
@admin.register(Penalty)
class PenaltyAdmin(admin.ModelAdmin):
    list_display = (
        'penalty_id', 'booking_link', 'penalty_type_colored', 'penalty_amount_colored',
        'status_colored', 'applied_to_link', 'rating_impact', 'created_at'
    )
    list_filter = ('penalty_type', 'status', 'created_at')
    search_fields = ('booking__booking_id', 'applied_to__full_name', 'description')
    raw_id_fields = ('booking', 'trip', 'applied_to', 'applied_by')
    actions = ['apply_penalties', 'waive_penalties', 'mark_pending']

    def booking_link(self, obj):
        link = reverse('admin:api_booking_change', args=[obj.booking.booking_id])
        return format_html('<a href="{}">Booking #{}</a>', link, str(obj.booking.booking_id))

    booking_link.short_description = 'Booking'

    def penalty_type_colored(self, obj):
        colors = {
            'wrong_delivery': 'red',
            'late_delivery': 'orange',
            'damaged_goods': 'brown',
            'misbehavior': 'purple',
            'cancellation': 'blue',
            'other': 'gray',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.penalty_type, 'black'),
            obj.get_penalty_type_display()
        )

    penalty_type_colored.short_description = 'Type'

    def penalty_amount_colored(self, obj):
        return format_html('<span style="color: red; font-weight: bold;">₹{}</span>', str(obj.penalty_amount))

    penalty_amount_colored.short_description = 'Amount'

    def status_colored(self, obj):
        colors = {
            'pending': 'orange',
            'applied': 'red',
            'waived': 'green',
            'disputed': 'blue',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.get_status_display()
        )

    status_colored.short_description = 'Status'

    def applied_to_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.applied_to.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.applied_to.full_name)

    applied_to_link.short_description = 'Applied To'

    def apply_penalties(self, request, queryset):
        queryset.update(status='applied', resolved_at=timezone.now())
        self.message_user(request, f"{queryset.count()} penalties applied.")

    apply_penalties.short_description = "Apply selected penalties"

    def waive_penalties(self, request, queryset):
        queryset.update(status='waived', resolved_at=timezone.now())
        self.message_user(request, f"{queryset.count()} penalties waived.")

    waive_penalties.short_description = "Waive selected penalties"

    def mark_pending(self, request, queryset):
        queryset.update(status='pending', resolved_at=None)
        self.message_user(request, f"{queryset.count()} penalties marked as pending.")

    mark_pending.short_description = "Mark as pending"


# ============ WALLET ADMIN ============
@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = (
        'wallet_id', 'user_link', 'balance_colored', 'reward_points_colored',
        'cashback_balance_colored', 'consumption_percentage', 'updated_at'
    )
    list_filter = ('currency',)
    search_fields = ('user__full_name', 'user__email')
    raw_id_fields = ('user',)
    actions = ['add_reward_points_100', 'add_cashback_500', 'reset_wallet']

    def user_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.user.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.user.full_name)

    user_link.short_description = 'User'

    def balance_colored(self, obj):
        if obj.balance > 10000:
            color = 'green'
        elif obj.balance > 5000:
            color = 'blue'
        else:
            color = 'orange'
        return format_html('<span style="color: {}; font-weight: bold;">₹{}</span>', color, str(obj.balance))

    balance_colored.short_description = 'Balance'

    def reward_points_colored(self, obj):
        if obj.reward_points > 1000:
            color = 'purple'
        elif obj.reward_points > 500:
            color = 'blue'
        else:
            color = 'gray'
        return format_html('<span style="color: {};">{} pts</span>', color, str(obj.reward_points))

    reward_points_colored.short_description = 'Reward Points'

    def cashback_balance_colored(self, obj):
        return format_html('<span style="color: green;">₹{}</span>', str(obj.cashback_balance))

    cashback_balance_colored.short_description = 'Cashback'

    def add_reward_points_100(self, request, queryset):
        for wallet in queryset:
            wallet.reward_points += 100
            wallet.save()
        self.message_user(request, f"Added 100 reward points to {queryset.count()} wallets.")

    add_reward_points_100.short_description = "Add 100 reward points"

    def add_cashback_500(self, request, queryset):
        for wallet in queryset:
            wallet.cashback_balance += 500
            wallet.save()
        self.message_user(request, f"Added ₹500 cashback to {queryset.count()} wallets.")

    add_cashback_500.short_description = "Add ₹500 cashback"

    def reset_wallet(self, request, queryset):
        for wallet in queryset:
            wallet.balance = 0
            wallet.reward_points = 0
            wallet.cashback_balance = 0
            wallet.save()
        self.message_user(request, f"Reset {queryset.count()} wallets.")

    reset_wallet.short_description = "Reset wallets to zero"


# ============ WALLET TRANSACTION ADMIN ============
@admin.register(WalletTransaction)
class WalletTransactionAdmin(admin.ModelAdmin):
    list_display = (
        'transaction_id', 'wallet_link', 'amount_colored', 'transaction_type_colored',
        'reference_type', 'reference_id', 'description_short', 'created_at'
    )
    list_filter = ('transaction_type', 'reference_type', 'created_at')
    search_fields = ('wallet__user__full_name', 'description')
    raw_id_fields = ('wallet',)

    def wallet_link(self, obj):
        link = reverse('admin:api_wallet_change', args=[obj.wallet.wallet_id])
        return format_html('<a href="{}">Wallet #{}</a>', link, str(obj.wallet.wallet_id))

    wallet_link.short_description = 'Wallet'

    def amount_colored(self, obj):
        color = 'green' if obj.transaction_type == 'credit' else 'red'
        return format_html('<span style="color: {}; font-weight: bold;">₹{}</span>', color, str(obj.amount))

    amount_colored.short_description = 'Amount'

    def transaction_type_colored(self, obj):
        color = 'green' if obj.transaction_type == 'credit' else 'red'
        return format_html('<span style="color: {};">{}</span>', color, obj.get_transaction_type_display())

    transaction_type_colored.short_description = 'Type'

    def description_short(self, obj):
        return obj.description[:30] + '...' if obj.description and len(obj.description) > 30 else obj.description

    description_short.short_description = 'Description'


# ============ PAYMENT ADMIN ============
@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = (
        'payment_id', 'booking_link', 'payer_link', 'payee_link', 'amount_colored',
        'payment_status_colored', 'payment_gateway', 'wallet_usage', 'created_at'
    )
    list_filter = ('payment_status', 'payment_gateway', 'created_at')
    search_fields = ('booking__booking_id', 'payer__full_name', 'payee__full_name')
    raw_id_fields = ('booking', 'payer', 'payee')
    actions = ['release_payments', 'refund_payments', 'mark_pending']

    def booking_link(self, obj):
        link = reverse('admin:api_booking_change', args=[obj.booking.booking_id])
        return format_html('<a href="{}">Booking #{}</a>', link, str(obj.booking.booking_id))

    booking_link.short_description = 'Booking'

    def payer_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.payer.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.payer.full_name)

    payer_link.short_description = 'Payer'

    def payee_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.payee.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.payee.full_name)

    payee_link.short_description = 'Payee'

    def amount_colored(self, obj):
        return format_html('<span style="color: green; font-weight: bold;">₹{}</span>', str(obj.amount))

    amount_colored.short_description = 'Amount'

    def payment_status_colored(self, obj):
        colors = {
            'pending': 'orange',
            'escrow_held': 'blue',
            'released_to_vendor': 'green',
            'refunded': 'purple',
            'failed': 'red',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.payment_status, 'black'),
            obj.get_payment_status_display()
        )

    payment_status_colored.short_description = 'Status'

    def wallet_usage(self, obj):
        if obj.wallet_amount_used > 0:
            percentage = (obj.wallet_amount_used / obj.amount) * 100
            return format_html('₹{} ({:.0f}%)', str(obj.wallet_amount_used), percentage)
        return "-"

    wallet_usage.short_description = 'Wallet Used'

    def release_payments(self, request, queryset):
        queryset.update(payment_status='released_to_vendor', released_at=timezone.now())
        self.message_user(request, f"{queryset.count()} payments released.")

    release_payments.short_description = "Release selected payments"

    def refund_payments(self, request, queryset):
        queryset.update(payment_status='refunded', released_at=timezone.now())
        self.message_user(request, f"{queryset.count()} payments refunded.")

    refund_payments.short_description = "Refund selected payments"

    def mark_pending(self, request, queryset):
        queryset.update(payment_status='pending', released_at=None)
        self.message_user(request, f"{queryset.count()} payments marked as pending.")

    mark_pending.short_description = "Mark as pending"


# ============ RATING ADMIN ============
@admin.register(Rating)
class RatingAdmin(admin.ModelAdmin):
    list_display = ('rating_id', 'booking_link', 'reviewer_link', 'reviewee_link',
                    'score_stars', 'comment_short', 'created_at')
    list_filter = ('score', 'created_at')
    search_fields = ('booking__booking_id', 'reviewer__full_name', 'reviewee__full_name')
    raw_id_fields = ('booking', 'reviewer', 'reviewee')

    def booking_link(self, obj):
        link = reverse('admin:api_booking_change', args=[obj.booking.booking_id])
        return format_html('<a href="{}">Booking #{}</a>', link, str(obj.booking.booking_id))

    booking_link.short_description = 'Booking'

    def reviewer_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.reviewer.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.reviewer.full_name)

    reviewer_link.short_description = 'Reviewer'

    def reviewee_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.reviewee.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.reviewee.full_name)

    reviewee_link.short_description = 'Reviewee'

    def score_stars(self, obj):
        stars = '★' * obj.score + '☆' * (5 - obj.score)
        return format_html('<span style="color: gold;">{}</span>', stars)

    score_stars.short_description = 'Score'

    def comment_short(self, obj):
        return obj.comment[:30] + '...' if obj.comment and len(obj.comment) > 30 else obj.comment

    comment_short.short_description = 'Comment'


# ============ DISPUTE ADMIN ============
@admin.register(Dispute)
class DisputeAdmin(admin.ModelAdmin):
    list_display = ('dispute_id', 'booking_link', 'raised_by_link', 'reason_category_colored',
                    'status_colored', 'description_short', 'created_at')
    list_filter = ('reason_category', 'status', 'created_at')
    search_fields = ('booking__booking_id', 'raised_by__full_name', 'description')
    raw_id_fields = ('booking', 'raised_by')
    actions = ['mark_investigating', 'mark_resolved', 'mark_closed']

    def booking_link(self, obj):
        link = reverse('admin:api_booking_change', args=[obj.booking.booking_id])
        return format_html('<a href="{}">Booking #{}</a>', link, str(obj.booking.booking_id))

    booking_link.short_description = 'Booking'

    def raised_by_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.raised_by.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.raised_by.full_name)

    raised_by_link.short_description = 'Raised By'

    def reason_category_colored(self, obj):
        colors = {
            'damaged_goods': 'red',
            'late_delivery': 'orange',
            'wrong_delivery': 'darkred',
            'payment_issue': 'blue',
            'vehicle_condition': 'brown',
            'other': 'gray',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.reason_category, 'black'),
            obj.get_reason_category_display()
        )

    reason_category_colored.short_description = 'Reason'

    def status_colored(self, obj):
        colors = {
            'open': 'red',
            'investigating': 'orange',
            'resolved': 'green',
            'closed': 'gray',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.status, 'black'),
            obj.get_status_display()
        )

    status_colored.short_description = 'Status'

    def description_short(self, obj):
        return obj.description[:30] + '...' if len(obj.description) > 30 else obj.description

    description_short.short_description = 'Description'

    def mark_investigating(self, request, queryset):
        queryset.update(status='investigating')
        self.message_user(request, f"{queryset.count()} disputes marked as investigating.")

    mark_investigating.short_description = "Mark as investigating"

    def mark_resolved(self, request, queryset):
        queryset.update(status='resolved')
        self.message_user(request, f"{queryset.count()} disputes marked as resolved.")

    mark_resolved.short_description = "Mark as resolved"

    def mark_closed(self, request, queryset):
        queryset.update(status='closed')
        self.message_user(request, f"{queryset.count()} disputes marked as closed.")

    mark_closed.short_description = "Mark as closed"


# ============ FESTIVAL GIFT ADMIN ============
@admin.register(FestivalGift)
class FestivalGiftAdmin(admin.ModelAdmin):
    list_display = (
        'gift_id', 'festival_colored', 'recipient_link', 'gift_type_colored',
        'gift_value_colored', 'minimum_rating', 'minimum_turnover', 'is_delivered', 'created_at'
    )
    list_filter = ('festival', 'gift_type', 'is_delivered')
    search_fields = ('recipient__full_name', 'gift_description')
    raw_id_fields = ('recipient', 'created_by')
    actions = ['mark_delivered', 'notify_eligible', 'duplicate_gift']

    def festival_colored(self, obj):
        colors = {
            'diwali': 'orange',
            'holi': 'red',
            'eid': 'green',
            'christmas': 'red',
            'new_year': 'gold',
            'other': 'gray',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.festival, 'black'),
            obj.get_festival_display()
        )

    festival_colored.short_description = 'Festival'

    def recipient_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.recipient.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.recipient.full_name)

    recipient_link.short_description = 'Recipient'

    def gift_type_colored(self, obj):
        colors = {
            'cash_bonus': 'green',
            'voucher': 'blue',
            'physical': 'purple',
            'other': 'gray',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.gift_type, 'black'),
            obj.get_gift_type_display()
        )

    gift_type_colored.short_description = 'Gift Type'

    def gift_value_colored(self, obj):
        return format_html('<span style="color: green; font-weight: bold;">₹{}</span>', str(obj.gift_value))

    gift_value_colored.short_description = 'Value'

    def mark_delivered(self, request, queryset):
        queryset.update(is_delivered=True, delivered_at=timezone.now())
        self.message_user(request, f"{queryset.count()} gifts marked as delivered.")

    mark_delivered.short_description = "Mark as delivered"

    def notify_eligible(self, request, queryset):
        notification_count = 0
        for gift in queryset:
            eligible_users = User.objects.filter(
                role__in=['driver', 'truck_owner', 'transporter'],
                rating__gte=gift.minimum_rating,
                annual_turnover__gte=gift.minimum_turnover,
                is_active=True
            )
            for user in eligible_users:
                Notification.objects.create(
                    user=user,
                    title=f'Festival Gift: {gift.get_festival_display()}',
                    message=f'You are eligible for a {gift.get_gift_type_display()} worth ₹{gift.gift_value}!',
                    type='festival_gift'
                )
                notification_count += 1
        self.message_user(request, f"Notifications sent for {notification_count} users.")

    notify_eligible.short_description = "Notify eligible users"

    def duplicate_gift(self, request, queryset):
        for gift in queryset:
            gift.pk = None
            gift.is_delivered = False
            gift.delivered_at = None
            gift.save()
        self.message_user(request, f"{queryset.count()} gifts duplicated.")

    duplicate_gift.short_description = "Duplicate selected gifts"


# ============ NOTIFICATION ADMIN ============
@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('notification_id', 'user_link', 'title_short', 'type_colored',
                    'is_read', 'created_at')
    list_filter = ('is_read', 'type', 'created_at')
    search_fields = ('user__full_name', 'title', 'message')
    raw_id_fields = ('user',)
    actions = ['mark_read', 'mark_unread', 'delete_old']

    def user_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.user.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.user.full_name)

    user_link.short_description = 'User'

    def title_short(self, obj):
        return obj.title[:30] + '...' if len(obj.title) > 30 else obj.title

    title_short.short_description = 'Title'

    def type_colored(self, obj):
        colors = {
            'booking': 'blue',
            'payment': 'green',
            'load': 'purple',
            'system': 'gray',
            'promo': 'orange',
            'security': 'red',
            'festival_gift': 'gold',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.type, 'black'),
            obj.get_type_display()
        )

    type_colored.short_description = 'Type'

    def mark_read(self, request, queryset):
        queryset.update(is_read=True)
        self.message_user(request, f"{queryset.count()} notifications marked as read.")

    mark_read.short_description = "Mark as read"

    def mark_unread(self, request, queryset):
        queryset.update(is_read=False)
        self.message_user(request, f"{queryset.count()} notifications marked as unread.")

    mark_unread.short_description = "Mark as unread"

    def delete_old(self, request, queryset):
        cutoff = timezone.now() - timedelta(days=30)
        count = Notification.objects.filter(created_at__lt=cutoff).count()
        Notification.objects.filter(created_at__lt=cutoff).delete()
        self.message_user(request, f"{count} old notifications deleted.")

    delete_old.short_description = "Delete notifications older than 30 days"


# ============ KYC DOCUMENT ADMIN ============
@admin.register(KYCDocument)
class KYCDocumentAdmin(admin.ModelAdmin):
    list_display = (
        'doc_id', 'user_link', 'document_type_colored', 'document_number',
        'verification_status_colored', 'expiry_date_colored', 'uploaded_at'
    )
    list_filter = ('document_type', 'verification_status', 'uploaded_at')
    search_fields = ('document_number', 'user__full_name', 'user__email')
    raw_id_fields = ('user',)
    actions = ['approve_documents', 'reject_documents']

    def user_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.user.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.user.full_name)

    user_link.short_description = 'User'

    def document_type_colored(self, obj):
        colors = {
            'aadhaar': 'orange',
            'pan': 'blue',
            'gst': 'purple',
            'dl': 'green',
            'rc': 'brown',
            'fitness': 'red',
            'insurance': 'darkgreen',
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors.get(obj.document_type, 'black'),
            obj.get_document_type_display()
        )

    document_type_colored.short_description = 'Document Type'

    def verification_status_colored(self, obj):
        colors = {
            'pending': 'orange',
            'approved': 'green',
            'rejected': 'red',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.verification_status, 'black'),
            obj.get_verification_status_display()
        )

    verification_status_colored.short_description = 'Status'

    def expiry_date_colored(self, obj):
        if obj.expiry_date:
            if obj.expiry_date < timezone.now().date():
                return format_html('<span style="color: red;">{} (Expired)</span>', str(obj.expiry_date))
            days_left = (obj.expiry_date - timezone.now().date()).days
            if days_left < 30:
                return format_html('<span style="color: orange;">{} ({} days left)</span>',
                                   str(obj.expiry_date), str(days_left))
        return str(obj.expiry_date) if obj.expiry_date else "-"

    expiry_date_colored.short_description = 'Expiry Date'

    def approve_documents(self, request, queryset):
        updated = queryset.update(verification_status='approved', rejection_reason=None)
        for doc in queryset:
            user = doc.user
            if KYCDocument.objects.filter(user=user, verification_status='approved').count() >= 2:
                user.is_verified = True
                user.save()
        self.message_user(request, f"{updated} documents approved.")

    approve_documents.short_description = "Approve selected documents"

    def reject_documents(self, request, queryset):
        rejection_reason = request.POST.get('rejection_reason', 'Rejected by admin')
        queryset.update(verification_status='rejected', rejection_reason=rejection_reason)
        self.message_user(request, f"{queryset.count()} documents rejected.")

    reject_documents.short_description = "Reject selected documents"


# ============ SAVED ADDRESS ADMIN ============
@admin.register(SavedAddress)
class SavedAddressAdmin(admin.ModelAdmin):
    list_display = ('address_id', 'user_link', 'address_label', 'city', 'state', 'postal_code')
    list_filter = ('city', 'state')
    search_fields = ('street_address', 'city', 'state', 'user__full_name')
    raw_id_fields = ('user',)

    def user_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.user.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.user.full_name)

    user_link.short_description = 'User'


# ============ ADMIN LOG ADMIN ============
@admin.register(AdminLog)
class AdminLogAdmin(admin.ModelAdmin):
    list_display = ('log_id', 'admin_user_link', 'action_type_colored', 'target_id',
                    'details_short', 'created_at')
    list_filter = ('action_type', 'created_at')
    search_fields = ('admin_user__full_name', 'action_type', 'details')
    readonly_fields = ('created_at',)

    def admin_user_link(self, obj):
        link = reverse('admin:api_user_change', args=[obj.admin_user.user_id])
        return format_html('<a href="{}">{}</a>', link, obj.admin_user.full_name)

    admin_user_link.short_description = 'Admin'

    def action_type_colored(self, obj):
        colors = {
            'USER_BLOCK': 'red',
            'USER_UNBLOCK': 'green',
            'KYC_APPROVE': 'green',
            'KYC_REJECT': 'red',
            'VEHICLE_VERIFY': 'green',
            'VEHICLE_REJECT': 'red',
            'PRICING_CREATE': 'blue',
            'PRICING_UPDATE': 'orange',
            'PRICING_DELETE': 'red',
            'CATEGORY_CREATE': 'purple',
            'CATEGORY_UPDATE': 'blue',
            'CATEGORY_DELETE': 'red',
            'DISPUTE_UPDATE': 'orange',
            'PRICE_RECALCULATION': 'brown',
        }
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            colors.get(obj.action_type, 'black'),
            obj.action_type
        )

    action_type_colored.short_description = 'Action'

    def details_short(self, obj):
        return obj.details[:50] + '...' if obj.details and len(obj.details) > 50 else obj.details

    details_short.short_description = 'Details'


# ============ CUSTOMIZE ADMIN SITE ============
admin.site.site_header = 'TempoLogi Administration'
admin.site.site_title = 'TempoLogi Admin'
admin.site.index_title = 'Dashboard'
admin.site.site_url = '/'

# Enable sidebar navigation
admin.site.enable_nav_sidebar = True