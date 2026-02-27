import uuid
import os
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.utils import timezone
from django.db.models import Q
from decimal import Decimal


# ============ FILE UPLOAD PATHS ============
def user_profile_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return os.path.join('profile_pics', f"user_{instance.user_id}", f"profile.{ext}")


def vehicle_photo_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return os.path.join('vehicle_photos', f"vehicle_{instance.vehicle.vehicle_id}", f"{instance.side}.{ext}")


def kyc_document_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return os.path.join('kyc_docs', f"user_{instance.user.user_id}", f"{instance.document_type}.{ext}")


def document_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return os.path.join('booking_docs', f"booking_{instance.booking_id}", filename)


# ============ USER MANAGER ============
class UserManager(BaseUserManager):
    def create_user(self, phone_number, full_name, role, email=None, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('Phone number is required')
        if not full_name:
            raise ValueError('Full name is required')
        if not role:
            raise ValueError('Role is required')

        if email:
            email = self.normalize_email(email)

        user = self.model(
            phone_number=phone_number,
            full_name=full_name,
            role=role,
            email=email,
            **extra_fields
        )

        if password:
            user.set_password(password)

        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, full_name, password=None, email=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('role', 'admin')
        extra_fields.setdefault('status', 'active')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(
            phone_number=phone_number,
            full_name=full_name,
            email=email,
            password=password,
            **extra_fields
        )


# ============ USER MODEL ============
class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('consignee', 'Consignee'),
        ('truck_owner', 'Truck Owner'),
        ('transporter', 'Transporter'),
        ('corporate', 'Corporate'),
        ('admin', 'Admin'),
        ('driver', 'Driver'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
        ('banned', 'Banned'),
    ]

    PLAN_CHOICES = [
        ('silver', 'Silver'),
        ('gold', 'Gold'),
        ('platinum', 'Platinum'),
    ]

    user_id = models.AutoField(primary_key=True, db_column='user_id')
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_number = models.CharField(
        max_length=20,
        unique=True,
        validators=[RegexValidator(r'^\d{10,20}$', 'Enter valid phone number')]
    )
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='consignee')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    is_verified = models.BooleanField(default=False)
    profile_image_url = models.ImageField(upload_to=user_profile_upload_path, null=True, blank=True)

    # Driver/Truck Owner specific fields
    plan_type = models.CharField(max_length=20, choices=PLAN_CHOICES, default='silver')
    rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.00)
    total_trips = models.IntegerField(default=0)
    successful_deliveries = models.IntegerField(default=0)
    wrong_deliveries = models.IntegerField(default=0)
    late_deliveries = models.IntegerField(default=0)
    visibility_score = models.DecimalField(max_digits=5, decimal_places=2, default=100.00)

    # Annual turnover for festival gifts
    annual_turnover = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    # Auth fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'phone_number', 'role']

    class Meta:
        db_table = 'users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['role', 'status']),
            models.Index(fields=['plan_type', 'visibility_score']),
        ]

    def __str__(self):
        return f"{self.full_name} ({self.email or self.phone_number})"

    @property
    def id(self):
        return self.user_id

    def update_visibility_score(self):
        """Update driver/truck owner visibility based on performance"""
        base_score = 100.00
        penalty = (self.wrong_deliveries * 10) + (self.late_deliveries * 5)
        self.visibility_score = max(0, base_score - penalty)
        self.save(update_fields=['visibility_score'])


# ============ OTP MODEL ============
class OTP(models.Model):
    OTP_TYPES = [
        ('email_registration', 'Email Registration'),
        ('phone_registration', 'Phone Registration'),
        ('password_reset', 'Password Reset'),
        ('delivery_otp', 'Delivery OTP'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    otp = models.CharField(max_length=6)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    is_used = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'otp_verifications'
        indexes = [
            models.Index(fields=['phone_number', 'otp_type', 'is_used', 'is_verified']),
            models.Index(fields=['email', 'otp_type', 'is_used', 'is_verified']),
        ]

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.email or self.phone_number} - {self.otp}"


# ============ CORPORATE PROFILE ============
class CorporateProfile(models.Model):
    corporate_id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='corporate_profile', db_column='user_id')
    company_name = models.CharField(max_length=150)
    gst_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    contact_person = models.CharField(max_length=100, null=True, blank=True)
    credit_limit = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    contract_start_date = models.DateField(null=True, blank=True)
    contract_end_date = models.DateField(null=True, blank=True)

    class Meta:
        db_table = 'corporate_profiles'


# ============ KYC DOCUMENTS ============
class KYCDocument(models.Model):
    DOCUMENT_TYPES = [
        ('aadhaar', 'Aadhaar'),
        ('pan', 'PAN'),
        ('gst', 'GST'),
        ('dl', 'Driving License'),
        ('rc', 'RC'),
        ('fitness', 'Fitness'),
        ('insurance', 'Insurance'),
    ]

    VERIFICATION_STATUS = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    doc_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='kyc_documents', db_column='user_id')
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPES)
    document_number = models.CharField(max_length=50)
    file_url = models.FileField(upload_to=kyc_document_upload_path)
    expiry_date = models.DateField(null=True, blank=True)
    verification_status = models.CharField(max_length=20, choices=VERIFICATION_STATUS, default='pending')
    rejection_reason = models.CharField(max_length=255, null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'kyc_documents'
        unique_together = ['user', 'document_type']


# ============ SAVED ADDRESSES ============
class SavedAddress(models.Model):
    address_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='addresses', db_column='user_id')
    address_label = models.CharField(max_length=50, null=True, blank=True)
    street_address = models.TextField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    longitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)

    class Meta:
        db_table = 'saved_addresses'


# ============ VEHICLE MODEL ============
class Vehicle(models.Model):
    VEHICLE_TYPES = [
        ('mini_truck', 'Mini Truck'),
        ('tempo', 'Tempo'),
        ('container', 'Container'),
        ('trailer', 'Trailer'),
        ('open_body', 'Open Body'),
    ]

    VERIFICATION_STATUS = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]

    vehicle_id = models.AutoField(primary_key=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vehicles', db_column='owner_id',
                              limit_choices_to={'role__in': ['truck_owner', 'transporter']})
    vehicle_type = models.CharField(max_length=20, choices=VEHICLE_TYPES)
    manufacturer = models.CharField(max_length=100, null=True, blank=True)
    registration_number = models.CharField(max_length=20, unique=True)
    registration_year = models.IntegerField(null=True, blank=True)
    capacity_ton = models.DecimalField(max_digits=10, decimal_places=2)
    length_ft = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    verification_status = models.CharField(max_length=20, choices=VERIFICATION_STATUS, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vehicles'
        indexes = [
            models.Index(fields=['owner']),
            models.Index(fields=['registration_number']),
            models.Index(fields=['vehicle_type', 'verification_status']),
        ]

    def __str__(self):
        return f"{self.registration_number} - {self.vehicle_type}"


# ============ VEHICLE PHOTOS ============
class VehiclePhoto(models.Model):
    SIDES = [
        ('front', 'Front'),
        ('back', 'Back'),
        ('left', 'Left'),
        ('right', 'Right'),
        ('interior', 'Interior'),
    ]

    photo_id = models.AutoField(primary_key=True)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='photos', db_column='vehicle_id')
    photo_url = models.ImageField(upload_to=vehicle_photo_upload_path)
    side = models.CharField(max_length=20, choices=SIDES)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vehicle_photos'
        unique_together = ['vehicle', 'side']


# ============ VEHICLE CATEGORY & PRICING ============
class VehicleCategory(models.Model):
    """Vehicle categories with detailed specifications"""
    category_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)  # e.g., "22 ft Container", "16 Ton Truck"
    vehicle_type = models.CharField(max_length=20, choices=Vehicle.VEHICLE_TYPES)

    # Specifications
    length_ft = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    capacity_ton = models.DecimalField(max_digits=10, decimal_places=2)

    # Base rates (₹7,000 for 240 km = ~₹29.17/km)
    base_rate_per_km = models.DecimalField(max_digits=10, decimal_places=2, default=30.00)
    base_distance_km = models.DecimalField(max_digits=10, decimal_places=2, default=240)
    base_charge = models.DecimalField(max_digits=10, decimal_places=2, default=7000)

    # Sample calculations
    sample_rate_10ton = models.DecimalField(max_digits=10, decimal_places=2, null=True,
                                            blank=True)  # ₹14,500 for Nagar-Solapur
    sample_rate_16ton = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    sample_rate_22ft = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    # Slab configuration
    slab_config = models.JSONField(default=dict, help_text="Rate slabs configuration")

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'vehicle_categories'
        unique_together = ['vehicle_type', 'capacity_ton', 'length_ft']
        indexes = [
            models.Index(fields=['vehicle_type', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} - {self.capacity_ton} ton"


class PricingSlab(models.Model):
    """Dynamic pricing slabs based on distance and weight"""
    SLAB_TYPES = [
        ('distance', 'Distance Based'),
        ('weight', 'Weight Based'),
        ('combined', 'Combined'),
    ]

    slab_id = models.AutoField(primary_key=True)
    vehicle_category = models.ForeignKey(VehicleCategory, on_delete=models.CASCADE, related_name='pricing_slabs')
    slab_type = models.CharField(max_length=20, choices=SLAB_TYPES, default='combined')

    # Distance slab (km)
    min_distance = models.IntegerField(default=0)
    max_distance = models.IntegerField(null=True, blank=True)

    # Weight slab (tons) - Example: 35 MT for 100 km
    min_weight_ton = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    max_weight_ton = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    # Rate calculation
    rate_per_km = models.DecimalField(max_digits=10, decimal_places=2, help_text="Rate per kilometer")
    rate_per_ton_km = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True,
                                          help_text="Rate per ton per km (e.g., 20 MT per ton)")

    # Base slab for minimum load (1000 kg)
    is_base_slab = models.BooleanField(default=False)
    base_weight_kg = models.IntegerField(default=1000)
    base_charge = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    # Minimum 5 km slab logic for part load
    min_distance_for_part_load = models.IntegerField(default=5)
    part_load_multiplier = models.DecimalField(max_digits=4, decimal_places=2, default=1.5)

    # Peak pricing
    peak_multiplier = models.DecimalField(max_digits=4, decimal_places=2, default=1.0)
    festival_multiplier = models.DecimalField(max_digits=4, decimal_places=2, default=1.0)
    requires_admin_approval = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'pricing_slabs'
        ordering = ['min_distance', 'min_weight_ton']
        indexes = [
            models.Index(fields=['vehicle_category', 'is_active']),
            models.Index(fields=['min_distance', 'max_distance']),
        ]

    def __str__(self):
        distance_range = f"{self.min_distance}-{self.max_distance or '∞'} km"
        weight_range = f"{self.min_weight_ton}-{self.max_weight_ton or '∞'} ton"
        return f"{self.vehicle_category.name} - {distance_range} / {weight_range}"


# ============ VEHICLE SCHEDULES ============
class VehicleSchedule(models.Model):
    TRIP_TYPES = [
        ('one_way', 'One Way'),
        ('return', 'Return'),
        ('tempopool', 'TempoPool'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('booked', 'Booked'),
        ('expired', 'Expired'),
    ]

    schedule_id = models.AutoField(primary_key=True)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='schedules', db_column='vehicle_id')
    start_location = models.CharField(max_length=255)
    end_location = models.CharField(max_length=255)
    start_lat = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    start_lng = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    end_lat = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    end_lng = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    available_from = models.DateTimeField()
    available_to = models.DateTimeField()
    available_capacity_ton = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    trip_type = models.CharField(max_length=20, choices=TRIP_TYPES, default='one_way')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')

    class Meta:
        db_table = 'vehicle_schedules'
        indexes = [
            models.Index(fields=['start_lat', 'start_lng']),
            models.Index(fields=['status', 'available_from', 'available_to']),
        ]


# ============ LOAD MODEL ============
class Load(models.Model):
    TRIP_MODES = [
        ('full_truck', 'Full Truck'),
        ('tempopool', 'TempoPool'),
        ('part_load', 'Part Load'),
    ]

    BOOKING_TYPES = [
        ('instant', 'Instant'),
        ('bidding', 'Bidding'),
    ]

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('assigned', 'Assigned'),
        ('in_transit', 'In Transit'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
    ]

    TRIP_TYPES = [
        ('one_way', 'One Way'),
        ('return', 'Return'),
    ]

    load_id = models.AutoField(primary_key=True)
    consignee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='loads', db_column='consignee_id',
                                  limit_choices_to={'role__in': ['consignee', 'corporate']})

    # Pickup
    pickup_address = models.TextField()
    pickup_lat = models.DecimalField(max_digits=10, decimal_places=8)
    pickup_lng = models.DecimalField(max_digits=10, decimal_places=8)

    # Drop
    drop_address = models.TextField()
    drop_lat = models.DecimalField(max_digits=10, decimal_places=8)
    drop_lng = models.DecimalField(max_digits=10, decimal_places=8)

    # Distance (auto-calculated)
    distance_km = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    material_type = models.CharField(max_length=100)
    weight_kg = models.DecimalField(max_digits=10, decimal_places=2)
    required_vehicle_category = models.ForeignKey(VehicleCategory, on_delete=models.SET_NULL, null=True)
    pickup_date = models.DateTimeField()
    is_fragile = models.BooleanField(default=False)
    special_instructions = models.TextField(null=True, blank=True)
    trip_mode = models.CharField(max_length=20, choices=TRIP_MODES, default='full_truck')
    booking_type = models.CharField(max_length=20, choices=BOOKING_TYPES, default='instant')
    trip_type = models.CharField(max_length=20, choices=TRIP_TYPES, default='one_way')

    # Price fields
    budget_price = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    is_price_auto_calculated = models.BooleanField(default=True)
    price_breakdown = models.JSONField(null=True, blank=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    is_deliverable = models.BooleanField(default=True)
    delivery_confirmed_before_dispatch = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'loads'
        indexes = [
            models.Index(fields=['pickup_lat', 'pickup_lng']),
            models.Index(fields=['status', 'pickup_date']),
            models.Index(fields=['consignee', 'status']),
            models.Index(fields=['is_deliverable']),
        ]

    def __str__(self):
        return f"Load #{self.load_id} - {self.material_type}"


# ============ LOAD REQUEST MODEL ============
class LoadRequest(models.Model):
    REQUEST_STATUS = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('withdrawn', 'Withdrawn'),
        ('expired', 'Expired'),
    ]

    request_id = models.AutoField(primary_key=True)
    load = models.ForeignKey(Load, on_delete=models.CASCADE, related_name='requests', db_column='load_id')
    requester = models.ForeignKey(User, on_delete=models.CASCADE, related_name='load_requests',
                                  db_column='requester_id',
                                  limit_choices_to={'role__in': ['truck_owner', 'transporter']})
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, db_column='vehicle_id')

    # Pricing details
    distance_km = models.DecimalField(max_digits=10, decimal_places=2)
    base_price = models.DecimalField(max_digits=15, decimal_places=2)
    weight_factor = models.DecimalField(max_digits=5, decimal_places=2, default=1.0)
    traffic_multiplier = models.DecimalField(max_digits=4, decimal_places=2, default=1.0)
    fuel_surcharge = models.DecimalField(max_digits=5, decimal_places=2, default=0.0)
    total_price = models.DecimalField(max_digits=15, decimal_places=2)

    message = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='pending')
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'load_requests'
        indexes = [
            models.Index(fields=['load', 'status']),
            models.Index(fields=['requester', 'status']),
        ]
        unique_together = ['load', 'requester']


# ============ TRIP MANAGEMENT ============
class Trip(models.Model):
    TRIP_STATUS = [
        ('scheduled', 'Scheduled'),
        ('confirmed', 'Confirmed'),
        ('boarding', 'At Boarding Point'),
        ('in_transit', 'In Transit'),
        ('halted', 'Halted'),
        ('delivered', 'Delivered'),
        ('cancelled', 'Cancelled'),
        ('delayed', 'Delayed'),
    ]

    trip_id = models.AutoField(primary_key=True)
    booking = models.OneToOneField('Booking', on_delete=models.CASCADE, related_name='trip', null=True, blank=True)
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='trips')
    driver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='driver_trips')
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_trips')

    # Trip details
    trip_type = models.CharField(max_length=20, choices=VehicleSchedule.TRIP_TYPES, default='one_way')

    # From - Current Location - Destination
    from_location = models.CharField(max_length=255)
    from_lat = models.DecimalField(max_digits=10, decimal_places=8)
    from_lng = models.DecimalField(max_digits=10, decimal_places=8)

    current_location = models.CharField(max_length=255, null=True, blank=True)
    current_lat = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    current_lng = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)

    destination = models.CharField(max_length=255)
    destination_lat = models.DecimalField(max_digits=10, decimal_places=8)
    destination_lng = models.DecimalField(max_digits=10, decimal_places=8)

    # Space availability for part load/return trip
    total_capacity_kg = models.DecimalField(max_digits=10, decimal_places=2)
    booked_capacity_kg = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    available_capacity_kg = models.DecimalField(max_digits=10, decimal_places=2)

    # For return trip offers
    is_return_trip_available = models.BooleanField(default=False)
    return_from_location = models.CharField(max_length=255, null=True, blank=True)
    return_from_lat = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    return_from_lng = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    return_destination = models.CharField(max_length=255, null=True, blank=True)
    return_available_from = models.DateTimeField(null=True, blank=True)
    return_available_to = models.DateTimeField(null=True, blank=True)

    # Timing
    scheduled_boarding_time = models.DateTimeField()
    actual_boarding_time = models.DateTimeField(null=True, blank=True)
    estimated_delivery_time = models.DateTimeField()
    actual_delivery_time = models.DateTimeField(null=True, blank=True)
    delivery_time_commitment = models.CharField(max_length=100, null=True, blank=True)

    # Haulting details
    is_halted = models.BooleanField(default=False)
    halt_start_time = models.DateTimeField(null=True, blank=True)
    halt_end_time = models.DateTimeField(null=True, blank=True)
    halt_location = models.CharField(max_length=255, null=True, blank=True)
    halt_reason = models.TextField(null=True, blank=True)

    # Rate change after 24 hours haulting
    original_rate = models.DecimalField(max_digits=15, decimal_places=2)
    adjusted_rate = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    rate_adjusted_at = models.DateTimeField(null=True, blank=True)
    rate_adjustment_reason = models.TextField(null=True, blank=True)

    # Status
    status = models.CharField(max_length=20, choices=TRIP_STATUS, default='scheduled')
    delay_minutes = models.IntegerField(default=0)
    delay_reason = models.TextField(null=True, blank=True)

    # Visibility settings
    is_visible_to_consignee = models.BooleanField(default=True)
    is_visible_to_transporter = models.BooleanField(default=True)
    is_visible_for_return_search = models.BooleanField(default=False)

    # Tracking
    last_location_update = models.DateTimeField(null=True, blank=True)
    location_history = models.JSONField(default=list, help_text="Track location history")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'trips'
        indexes = [
            models.Index(fields=['status', 'estimated_delivery_time']),
            models.Index(fields=['current_lat', 'current_lng']),
            models.Index(fields=['is_visible_for_return_search', 'available_capacity_kg']),
            models.Index(fields=['from_lat', 'from_lng', 'destination_lat', 'destination_lng']),
        ]

    def __str__(self):
        return f"Trip #{self.trip_id} - {self.from_location} → {self.destination}"

    def update_available_capacity(self):
        self.available_capacity_kg = self.total_capacity_kg - self.booked_capacity_kg
        self.save(update_fields=['available_capacity_kg'])

    def calculate_delay(self):
        if self.status == 'delayed' and self.estimated_delivery_time:
            now = timezone.now()
            if now > self.estimated_delivery_time:
                delay = (now - self.estimated_delivery_time).total_seconds() / 60
                self.delay_minutes = int(delay)
                self.save(update_fields=['delay_minutes'])
        return self.delay_minutes


class TripLocation(models.Model):
    """Detailed trip location tracking"""
    location_id = models.BigAutoField(primary_key=True)
    trip = models.ForeignKey(Trip, on_delete=models.CASCADE, related_name='locations')
    latitude = models.DecimalField(max_digits=10, decimal_places=8)
    longitude = models.DecimalField(max_digits=10, decimal_places=8)
    location_address = models.CharField(max_length=255, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'trip_locations'
        ordering = ['-timestamp']


# ============ RETURN TRIP OFFERS ============
class ReturnTripOffer(models.Model):
    """Return trip offers for load matching"""
    offer_id = models.AutoField(primary_key=True)
    original_trip = models.ForeignKey(Trip, on_delete=models.CASCADE, related_name='return_offers')

    # Offer details
    from_location = models.CharField(max_length=255)
    from_lat = models.DecimalField(max_digits=10, decimal_places=8)
    from_lng = models.DecimalField(max_digits=10, decimal_places=8)
    to_location = models.CharField(max_length=255)
    to_lat = models.DecimalField(max_digits=10, decimal_places=8)
    to_lng = models.DecimalField(max_digits=10, decimal_places=8)

    available_space_kg = models.DecimalField(max_digits=10, decimal_places=2)
    available_from = models.DateTimeField()
    available_to = models.DateTimeField()

    # Pricing
    offered_price = models.DecimalField(max_digits=15, decimal_places=2)
    is_negotiable = models.BooleanField(default=True)

    # Status
    is_active = models.BooleanField(default=True)
    is_booked = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'return_trip_offers'
        indexes = [
            models.Index(fields=['from_lat', 'from_lng']),
            models.Index(fields=['is_active', 'available_from']),
        ]


# ============ BOOKING MODEL ============
class Booking(models.Model):
    BOOKING_STATUS = [
        ('confirmed', 'Confirmed'),
        ('driver_assigned', 'Driver Assigned'),
        ('at_pickup', 'At Pickup'),
        ('loaded', 'Loaded'),
        ('in_transit', 'In Transit'),
        ('at_delivery', 'At Delivery'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('delayed', 'Delayed'),
    ]

    booking_id = models.AutoField(primary_key=True)
    load = models.OneToOneField(Load, on_delete=models.CASCADE, related_name='booking', db_column='load_id')
    consignee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bookings_as_consignee',
                                  db_column='consignee_id')
    transporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bookings_as_transporter',
                                    db_column='transporter_id')
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, db_column='vehicle_id')
    driver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                               related_name='assigned_bookings', db_column='driver_id',
                               limit_choices_to={'role': 'driver'})

    agreed_price = models.DecimalField(max_digits=15, decimal_places=2)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    total_amount = models.DecimalField(max_digits=15, decimal_places=2)

    pickup_otp = models.CharField(max_length=6, null=True, blank=True)
    delivery_otp = models.CharField(max_length=6, null=True, blank=True)

    booking_status = models.CharField(max_length=20, choices=BOOKING_STATUS, default='confirmed')

    # Delivery commitment
    delivery_time_commitment = models.DateTimeField(null=True, blank=True)
    actual_delivery_time = models.DateTimeField(null=True, blank=True)

    # Documents
    eway_bill_no = models.CharField(max_length=50, null=True, blank=True)
    invoice_url = models.CharField(max_length=255, null=True, blank=True)
    bilty_url = models.CharField(max_length=255, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'bookings'
        indexes = [
            models.Index(fields=['booking_status']),
            models.Index(fields=['consignee', 'booking_status']),
            models.Index(fields=['transporter', 'booking_status']),
            models.Index(fields=['driver', 'booking_status']),
        ]


# ============ EXTRA CHARGES ============
class ExtraCharge(models.Model):
    """Additional charges like Hamali, Loading/Unloading, etc."""
    CHARGE_TYPES = [
        ('hamali', 'Hamali Payment'),
        ('loading', 'Loading Charges'),
        ('unloading', 'Unloading Charges'),
        ('handling', 'Handling Charges'),
        ('haulting', 'Haulting Charges'),
        ('local_delivery', 'Local Delivery'),
        ('waiting', 'Waiting Charges'),
        ('penalty', 'Penalty'),
        ('other', 'Other'),
    ]

    charge_id = models.AutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='extra_charges')
    charge_type = models.CharField(max_length=20, choices=CHARGE_TYPES)
    description = models.CharField(max_length=255)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    is_mandatory = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = 'extra_charges'


# ============ PENALTY & DELAY MANAGEMENT ============
class Penalty(models.Model):
    """Penalty for wrong delivery, delays, etc."""
    PENALTY_TYPES = [
        ('wrong_delivery', 'Wrong Delivery'),
        ('late_delivery', 'Late Delivery'),
        ('damaged_goods', 'Damaged Goods'),
        ('misbehavior', 'Driver Misbehavior'),
        ('cancellation', 'Late Cancellation'),
        ('other', 'Other'),
    ]

    PENALTY_STATUS = [
        ('pending', 'Pending Review'),
        ('applied', 'Applied'),
        ('waived', 'Waived'),
        ('disputed', 'Disputed'),
    ]

    penalty_id = models.AutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='penalties')
    trip = models.ForeignKey(Trip, on_delete=models.CASCADE, null=True)

    penalty_type = models.CharField(max_length=20, choices=PENALTY_TYPES)
    description = models.TextField()

    # Penalty calculation
    penalty_amount = models.DecimalField(max_digits=10, decimal_places=2)
    delay_minutes = models.IntegerField(null=True, blank=True)
    delay_rate_per_minute = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)

    # Impact on rating/visibility
    rating_impact = models.IntegerField(default=0, help_text="Negative impact on rating (-1 to -5)")
    visibility_reduction_days = models.IntegerField(default=0)

    status = models.CharField(max_length=20, choices=PENALTY_STATUS, default='pending')
    applied_to = models.ForeignKey(User, on_delete=models.CASCADE, related_name='penalties_received')
    applied_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='penalties_applied')

    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'penalties'
        indexes = [
            models.Index(fields=['status', 'applied_to']),
            models.Index(fields=['penalty_type']),
        ]


# ============ SHIPMENT TRACKING ============
class ShipmentTracking(models.Model):
    tracking_id = models.BigAutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='tracking_updates',
                                db_column='booking_id')
    latitude = models.DecimalField(max_digits=10, decimal_places=8)
    longitude = models.DecimalField(max_digits=10, decimal_places=8)
    current_location_text = models.CharField(max_length=255, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'shipment_tracking'
        ordering = ['-timestamp']


# ============ WALLET MODEL ============
class Wallet(models.Model):
    wallet_id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet', db_column='user_id')
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=3, default='INR')

    # Rewards and cashback (virtual money)
    reward_points = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    cashback_balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    # Consumption rules: 10% per trip
    consumption_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=10.00)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'wallets'


# ============ WALLET TRANSACTION ============
class WalletTransaction(models.Model):
    TRANSACTION_TYPES = [
        ('credit', 'Credit'),
        ('debit', 'Debit'),
    ]

    REFERENCE_TYPES = [
        ('booking_payment', 'Booking Payment'),
        ('refund', 'Refund'),
        ('withdrawal', 'Withdrawal'),
        ('deposit', 'Deposit'),
        ('penalty', 'Penalty'),
        ('reward', 'Reward'),
        ('cashback', 'Cashback'),
    ]

    transaction_id = models.AutoField(primary_key=True)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions', db_column='wallet_id')
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    reference_type = models.CharField(max_length=20, choices=REFERENCE_TYPES)
    reference_id = models.IntegerField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'wallet_transactions'


# ============ PAYMENT MODEL ============
class Payment(models.Model):
    PAYMENT_GATEWAYS = [
        ('razorpay', 'Razorpay'),
        ('paytm', 'Paytm'),
        ('cashfree', 'Cashfree'),
        ('cod', 'COD'),
        ('wallet', 'Wallet'),
    ]

    PAYMENT_STATUS = [
        ('pending', 'Pending'),
        ('escrow_held', 'Escrow Held'),
        ('released_to_vendor', 'Released to Vendor'),
        ('refunded', 'Refunded'),
        ('failed', 'Failed'),
    ]

    payment_id = models.AutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='payments', db_column='booking_id')
    payer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments_made', db_column='payer_id')
    payee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments_received', db_column='payee_id')
    amount = models.DecimalField(max_digits=15, decimal_places=2)

    payment_gateway = models.CharField(max_length=20, choices=PAYMENT_GATEWAYS)
    gateway_txn_id = models.CharField(max_length=100, null=True, blank=True)

    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='pending')

    admin_commission = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    vendor_payout = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    # Wallet consumption
    wallet_amount_used = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    cash_amount_paid = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    created_at = models.DateTimeField(auto_now_add=True)
    released_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'payments'


# ============ RATING MODEL ============
class Rating(models.Model):
    rating_id = models.AutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='ratings', db_column='booking_id')
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ratings_given', db_column='reviewer_id')
    reviewee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ratings_received',
                                 db_column='reviewee_id')
    score = models.IntegerField()
    comment = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'ratings'
        unique_together = ['booking', 'reviewer']


# ============ DISPUTE MODEL ============
class Dispute(models.Model):
    REASON_CATEGORIES = [
        ('damaged_goods', 'Damaged Goods'),
        ('late_delivery', 'Late Delivery'),
        ('wrong_delivery', 'Wrong Delivery'),
        ('payment_issue', 'Payment Issue'),
        ('vehicle_condition', 'Vehicle Condition'),
        ('other', 'Other'),
    ]

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('investigating', 'Investigating'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed'),
    ]

    dispute_id = models.AutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='disputes', db_column='booking_id')
    raised_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='disputes_raised', db_column='raised_by')
    reason_category = models.CharField(max_length=20, choices=REASON_CATEGORIES)
    description = models.TextField()
    evidence_url = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    admin_notes = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'disputes'


# ============ NOTIFICATION MODEL ============
class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('booking', 'Booking'),
        ('payment', 'Payment'),
        ('load', 'Load'),
        ('system', 'System'),
        ('promo', 'Promo'),
        ('security', 'Security'),
        ('festival_gift', 'Festival Gift'),
    ]

    notification_id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications', db_column='user_id')
    title = models.CharField(max_length=100)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES, default='system')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_read']),
        ]


# ============ ADMIN LOG MODEL ============
class AdminLog(models.Model):
    log_id = models.AutoField(primary_key=True)
    admin_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_logs', db_column='admin_user_id')
    action_type = models.CharField(max_length=50)
    target_id = models.IntegerField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'admin_logs'
        ordering = ['-created_at']


# ============ FESTIVAL GIFT MODEL ============
class FestivalGift(models.Model):
    FESTIVAL_TYPES = [
        ('diwali', 'Diwali'),
        ('holi', 'Holi'),
        ('eid', 'Eid'),
        ('christmas', 'Christmas'),
        ('new_year', 'New Year'),
        ('other', 'Other'),
    ]

    GIFT_TYPES = [
        ('cash_bonus', 'Cash Bonus'),
        ('voucher', 'Gift Voucher'),
        ('physical', 'Physical Gift'),
        ('other', 'Other'),
    ]

    gift_id = models.AutoField(primary_key=True)
    festival = models.CharField(max_length=20, choices=FESTIVAL_TYPES)
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='festival_gifts')
    gift_type = models.CharField(max_length=20, choices=GIFT_TYPES)
    gift_value = models.DecimalField(max_digits=10, decimal_places=2)
    gift_description = models.TextField()

    # Eligibility based on rating and turnover
    minimum_rating = models.DecimalField(max_digits=3, decimal_places=2, default=4.0)
    minimum_turnover = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    is_delivered = models.BooleanField(default=False)
    delivered_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='gifts_created')

    class Meta:
        db_table = 'festival_gifts'
        indexes = [
            models.Index(fields=['festival', 'is_delivered']),
        ]