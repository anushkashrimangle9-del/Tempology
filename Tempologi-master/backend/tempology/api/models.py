import uuid
import os
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator
from django.utils import timezone


# ============ FILE UPLOAD PATHS ============
def user_profile_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return os.path.join('profile_pics', f"user_{instance.id}", f"profile.{ext}")


def vehicle_photo_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return os.path.join('vehicle_photos', f"vehicle_{instance.vehicle.vehicle_id}", f"{instance.side}.{ext}")


def kyc_document_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return os.path.join('kyc_docs', f"user_{instance.user.id}", f"{instance.document_type}.{ext}")


# ============ USER MANAGER ============
class UserManager(BaseUserManager):
    def create_user(self, phone_number, full_name, role, email=None, password=None, **extra_fields):
        """
        Create and save a regular user.
        """
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
        """
        Create and save a superuser.
        """
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

    id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True, null=True, blank=True)
    phone_number = models.CharField(
        max_length=10,
        unique=True,
        validators=[RegexValidator(r'^\d{10}$', 'Enter valid 10-digit number')]
    )
    password = models.CharField(max_length=255)  # This is the standard Django password field
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='consignee')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    is_verified = models.BooleanField(default=False)
    profile_image = models.ImageField(upload_to=user_profile_upload_path, null=True, blank=True)

    # Auth fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'  # Changed to email for email login
    REQUIRED_FIELDS = ['full_name', 'phone_number', 'role']  # These are required when creating superuser

    class Meta:
        db_table = 'users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['phone_number']),
        ]

    def __str__(self):
        return f"{self.full_name} ({self.email or self.phone_number})"


# ============ OTP MODEL ============
class OTP(models.Model):
    OTP_TYPES = [
        ('registration', 'Registration'),
        ('password_reset', 'Password Reset'),
        ('email_verification', 'Email Verification'),
        ('phone_verification', 'Phone Verification'),
        ('login', 'Login'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(max_length=10, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    otp = models.CharField(max_length=4)
    otp_type = models.CharField(max_length=20, choices=OTP_TYPES)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'otp_verifications'
        indexes = [
            models.Index(fields=['phone_number', 'otp_type', 'is_used']),
            models.Index(fields=['email', 'otp_type', 'is_used']),
        ]

    def is_expired(self):
        return timezone.now() > self.expires_at

    def __str__(self):
        return f"{self.email or self.phone_number} - {self.otp}"


# ============ CORPORATE PROFILE ============
class CorporateProfile(models.Model):
    corporate_id = models.AutoField(primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='corporate_profile')
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
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='kyc_documents')
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPES)
    document_number = models.CharField(max_length=50)
    file = models.FileField(upload_to=kyc_document_upload_path)
    expiry_date = models.DateField(null=True, blank=True)
    verification_status = models.CharField(max_length=20, choices=VERIFICATION_STATUS, default='pending')
    rejection_reason = models.CharField(max_length=255, null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'kyc_documents'


# ============ SAVED ADDRESSES ============
class SavedAddress(models.Model):
    address_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='addresses')
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
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vehicles',
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
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='photos')
    photo = models.ImageField(upload_to=vehicle_photo_upload_path)
    side = models.CharField(max_length=20, choices=SIDES)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vehicle_photos'
        unique_together = ['vehicle', 'side']


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
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE, related_name='schedules')
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
        ]


# ============ LOAD MODEL ============
class Load(models.Model):
    TRIP_MODES = [
        ('full_truck', 'Full Truck'),
        ('tempopool', 'TempoPool'),
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

    load_id = models.AutoField(primary_key=True)
    consignee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='loads',
                                  limit_choices_to={'role__in': ['consignee', 'corporate']})

    # Pickup
    pickup_address = models.TextField()
    pickup_lat = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    pickup_lng = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)

    # Drop
    drop_address = models.TextField()
    drop_lat = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    drop_lng = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)

    material_type = models.CharField(max_length=100)
    weight_kg = models.DecimalField(max_digits=10, decimal_places=2)
    required_vehicle_type = models.CharField(max_length=50, null=True, blank=True)
    pickup_date = models.DateTimeField()
    is_fragile = models.BooleanField(default=False)
    special_instructions = models.TextField(null=True, blank=True)
    trip_mode = models.CharField(max_length=20, choices=TRIP_MODES, default='full_truck')
    booking_type = models.CharField(max_length=20, choices=BOOKING_TYPES, default='instant')
    budget_price = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'loads'
        indexes = [
            models.Index(fields=['pickup_lat', 'pickup_lng']),
        ]


# ============ BID MODEL ============
class Bid(models.Model):
    BID_STATUS = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('rejected', 'Rejected'),
        ('withdrawn', 'Withdrawn'),
    ]

    bid_id = models.AutoField(primary_key=True)
    load = models.ForeignKey(Load, on_delete=models.CASCADE, related_name='bids')
    transporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bids')
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    bid_amount = models.DecimalField(max_digits=15, decimal_places=2)
    bid_message = models.TextField(null=True, blank=True)
    bid_status = models.CharField(max_length=20, choices=BID_STATUS, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'bids'
        unique_together = ['load', 'transporter']


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
    ]

    booking_id = models.AutoField(primary_key=True)
    load = models.OneToOneField(Load, on_delete=models.CASCADE, related_name='booking')
    consignee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bookings_as_consignee')
    transporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bookings_as_transporter')
    vehicle = models.ForeignKey(Vehicle, on_delete=models.CASCADE)
    driver = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_bookings',
                               limit_choices_to={'role': 'driver'})

    agreed_price = models.DecimalField(max_digits=15, decimal_places=2)
    tax_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    total_amount = models.DecimalField(max_digits=15, decimal_places=2)

    pickup_otp = models.CharField(max_length=6, null=True, blank=True)
    delivery_otp = models.CharField(max_length=6, null=True, blank=True)

    booking_status = models.CharField(max_length=20, choices=BOOKING_STATUS, default='confirmed')

    # Documents
    eway_bill_no = models.CharField(max_length=50, null=True, blank=True)
    invoice = models.CharField(max_length=255, null=True, blank=True)
    bilty = models.CharField(max_length=255, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'bookings'


# ============ SHIPMENT TRACKING ============
class ShipmentTracking(models.Model):
    tracking_id = models.BigAutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='tracking_updates')
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
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=3, default='INR')
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
    ]

    transaction_id = models.AutoField(primary_key=True)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
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
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='payments')
    payer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments_made')
    payee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments_received')
    amount = models.DecimalField(max_digits=15, decimal_places=2)

    payment_gateway = models.CharField(max_length=20, choices=PAYMENT_GATEWAYS)
    gateway_txn_id = models.CharField(max_length=100, null=True, blank=True)

    payment_status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='pending')

    admin_commission = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    vendor_payout = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

    created_at = models.DateTimeField(auto_now_add=True)
    released_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'payments'


# ============ RATING MODEL ============
class Rating(models.Model):
    rating_id = models.AutoField(primary_key=True)
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='ratings')
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ratings_given')
    reviewee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ratings_received')
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
    booking = models.ForeignKey(Booking, on_delete=models.CASCADE, related_name='disputes')
    raised_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='disputes_raised')
    reason_category = models.CharField(max_length=20, choices=REASON_CATEGORIES)
    description = models.TextField()
    evidence = models.CharField(max_length=255, null=True, blank=True)
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
        ('system', 'System'),
        ('promo', 'Promo'),
    ]

    notification_id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=100, null=True, blank=True)
    message = models.TextField(null=True, blank=True)
    is_read = models.BooleanField(default=False)
    type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES, default='system')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notifications'
        ordering = ['-created_at']


# ============ ADMIN LOG MODEL ============
class AdminLog(models.Model):
    log_id = models.AutoField(primary_key=True)
    admin_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_logs')
    action_type = models.CharField(max_length=50)
    target_id = models.IntegerField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'admin_logs'