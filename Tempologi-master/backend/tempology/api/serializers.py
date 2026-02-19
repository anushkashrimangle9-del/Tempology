from rest_framework import serializers
from .models import *
from django.utils import timezone
import random
from datetime import timedelta
import base64
from django.core.files.base import ContentFile
import uuid
import six
import binascii
import imghdr

# ============ BASE64 IMAGE FIELD ============
class Base64ImageField(serializers.ImageField):
    def to_internal_value(self, data):
        if isinstance(data, six.string_types):
            if 'data:' in data and ';base64,' in data:
                header, data = data.split(';base64,')
            try:
                decoded_file = base64.b64decode(data)
            except (TypeError, binascii.Error):
                self.fail('invalid_image')

            file_name = str(uuid.uuid4())[:12]
            file_extension = self.get_file_extension(file_name, decoded_file)
            complete_file_name = f"{file_name}.{file_extension}"
            data = ContentFile(decoded_file, name=complete_file_name)

        return super().to_internal_value(data)

    def get_file_extension(self, file_name, decoded_file):
        extension = imghdr.what(file_name, decoded_file)
        return extension or 'jpg'


# ============ USER SERIALIZERS ============
class UserSerializer(serializers.ModelSerializer):
    profile_image_url = Base64ImageField(required=False, allow_null=True)

    class Meta:
        model = User
        fields = [
            'user_id', 'full_name', 'email', 'phone_number', 'role',
            'status', 'is_verified', 'profile_image_url', 'created_at'
        ]
        read_only_fields = ['user_id', 'is_verified', 'created_at']



# ============ REGISTRATION SERIALIZERS ============
class RegistrationInitSerializer(serializers.Serializer):
    """Initial registration - collects user data and sends OTPs"""
    full_name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=20, min_length=10)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)
    password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        # Check if email already exists
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({"email": "User with this email already exists"})

        # Check if phone already exists
        if User.objects.filter(phone_number=data['phone_number']).exists():
            raise serializers.ValidationError({"phone_number": "User with this phone number already exists"})

        return data


class VerifyEmailOTPSerializer(serializers.Serializer):
    """Verify email OTP during registration"""
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    full_name = serializers.CharField(max_length=100, required=False)
    phone_number = serializers.CharField(max_length=20, min_length=10, required=False)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES, required=False)
    password = serializers.CharField(write_only=True, min_length=6, required=False)

    def validate(self, data):
        email = data.get('email')
        otp_value = data.get('otp')

        # Find the OTP
        try:
            otp_obj = OTP.objects.filter(
                email=email,
                otp_type='email_registration',
                is_used=False,
                is_verified=False,
                expires_at__gt=timezone.now()
            ).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"otp": "Email OTP not found, expired, or already used"})

        if otp_obj.otp != otp_value:
            raise serializers.ValidationError({"otp": "Incorrect email OTP"})

        data['otp_instance'] = otp_obj
        return data


class VerifyPhoneOTPSerializer(serializers.Serializer):
    """Verify phone OTP during registration"""
    phone_number = serializers.CharField(max_length=20, min_length=10)
    otp = serializers.CharField(max_length=6)
    email = serializers.EmailField(required=False)  # Optional, for context

    def validate(self, data):
        phone = data.get('phone_number')
        otp_value = data.get('otp')

        # Find the OTP
        try:
            otp_obj = OTP.objects.filter(
                phone_number=phone,
                otp_type='phone_registration',
                is_used=False,
                is_verified=False,
                expires_at__gt=timezone.now()
            ).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"otp": "Phone OTP not found, expired, or already used"})

        if otp_obj.otp != otp_value:
            raise serializers.ValidationError({"otp": "Incorrect phone OTP"})

        data['otp_instance'] = otp_obj
        return data


class CompleteRegistrationSerializer(serializers.Serializer):
    """Complete registration after both OTPs are verified"""
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=20, min_length=10)
    full_name = serializers.CharField(max_length=100)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)
    password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        email = data.get('email')
        phone = data.get('phone_number')

        # Check if user already exists (shouldn't, but double-check)
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "User with this email already exists"})

        if User.objects.filter(phone_number=phone).exists():
            raise serializers.ValidationError({"phone_number": "User with this phone number already exists"})

        # Verify both OTPs are verified
        email_otp_verified = OTP.objects.filter(
            email=email,
            otp_type='email_registration',
            is_verified=True,
            is_used=False  # Not used yet, just verified
        ).exists()

        phone_otp_verified = OTP.objects.filter(
            phone_number=phone,
            otp_type='phone_registration',
            is_verified=True,
            is_used=False
        ).exists()

        if not email_otp_verified:
            raise serializers.ValidationError({"email": "Email not verified. Please verify email OTP first."})

        if not phone_otp_verified:
            raise serializers.ValidationError({"phone_number": "Phone not verified. Please verify phone OTP first."})

        return data


# ============ LOGIN SERIALIZERS (Email only) ============
class EmailLoginSerializer(serializers.Serializer):
    """Login with email and password (NO VERIFICATION REQUIRED)"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            raise serializers.ValidationError("Both email and password are required")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid password")

        if not user.is_active or user.status != 'active':
            raise serializers.ValidationError("Account is not active")

        data['user'] = user
        return data


# ============ OTP SERIALIZERS ============
class SendOTPSerializer(serializers.Serializer):
    """Send OTP for registration (email or phone)"""
    contact = serializers.CharField(max_length=100)
    contact_type = serializers.ChoiceField(choices=['email', 'phone'])
    otp_type = serializers.ChoiceField(choices=['email_registration', 'phone_registration', 'password_reset'])

    def validate(self, data):
        contact = data.get('contact')
        contact_type = data.get('contact_type')
        otp_type = data.get('otp_type')

        # Validate format
        if contact_type == 'email':
            if '@' not in contact or '.' not in contact:
                raise serializers.ValidationError({"contact": "Invalid email format"})

            # For registration, check if email already exists
            if otp_type == 'email_registration':
                if User.objects.filter(email=contact).exists():
                    raise serializers.ValidationError({"contact": "Email already registered"})

        elif contact_type == 'phone':
            if not contact.isdigit() or len(contact) < 10 or len(contact) > 15:
                raise serializers.ValidationError({"contact": "Invalid phone number format"})

            # For registration, check if phone already exists
            if otp_type == 'phone_registration':
                if User.objects.filter(phone_number=contact).exists():
                    raise serializers.ValidationError({"contact": "Phone number already registered"})

        return data


class VerifyOTPSerializer(serializers.Serializer):
    """Verify OTP (marks as verified, not used)"""
    contact = serializers.CharField(max_length=100)
    contact_type = serializers.ChoiceField(choices=['email', 'phone'])
    otp = serializers.CharField(max_length=6)
    otp_type = serializers.ChoiceField(choices=['email_registration', 'phone_registration', 'password_reset'])

    def validate(self, data):
        contact = data.get('contact')
        contact_type = data.get('contact_type')
        otp_value = data.get('otp')
        otp_type = data.get('otp_type')

        # Build filter
        filter_kwargs = {
            'otp_type': otp_type,
            'is_used': False,
            'is_verified': False,
            'expires_at__gt': timezone.now()
        }

        if contact_type == 'email':
            filter_kwargs['email'] = contact
        else:
            filter_kwargs['phone_number'] = contact

        try:
            otp_obj = OTP.objects.filter(**filter_kwargs).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"otp": "OTP not found, expired, or already used"})

        if otp_obj.otp != otp_value:
            raise serializers.ValidationError({"otp": "Incorrect OTP"})

        data['otp_instance'] = otp_obj
        return data


# ============ PASSWORD MANAGEMENT SERIALIZERS ============
class ForgotPasswordSerializer(serializers.Serializer):
    """Forgot password - send OTP to email"""
    email = serializers.EmailField()

    def validate(self, data):
        email = data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email")

        data['user'] = user
        return data


class ResetPasswordSerializer(serializers.Serializer):
    """Reset password with OTP"""
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        email = data.get('email')

        # Find user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")

        # Verify OTP
        try:
            otp_obj = OTP.objects.filter(
                email=email,
                otp_type='password_reset',
                is_used=False,
                expires_at__gt=timezone.now()
            ).latest('created_at')
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"otp": "Invalid or expired OTP"})

        if otp_obj.otp != data['otp']:
            raise serializers.ValidationError({"otp": "Incorrect OTP"})

        data['user'] = user
        data['otp_instance'] = otp_obj
        return data


# ... rest of your serializers (UserSerializer, etc.) remain the same


class ChangePasswordSerializer(serializers.Serializer):
    """Change password serializer"""
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        user = self.context['request'].user
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError({"old_password": "Current password is incorrect"})

        return data


class ProfileUpdateSerializer(serializers.ModelSerializer):
    profile_image_url = Base64ImageField(required=False, allow_null=True)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'phone_number', 'profile_image_url']

    def validate_email(self, value):
        if value and value != self.instance.email:
            if User.objects.filter(email=value).exists():
                raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_phone_number(self, value):
        if value and value != self.instance.phone_number:
            if User.objects.filter(phone_number=value).exists():
                raise serializers.ValidationError("A user with this phone number already exists.")
        return value




# ============ KYC DOCUMENT SERIALIZERS ============
class KYCDocumentSerializer(serializers.ModelSerializer):
    file_url = Base64ImageField(required=True)

    class Meta:
        model = KYCDocument
        fields = [
            'doc_id', 'document_type', 'document_number', 'file_url',
            'expiry_date', 'verification_status', 'rejection_reason', 'uploaded_at'
        ]
        read_only_fields = ['doc_id', 'verification_status', 'rejection_reason', 'uploaded_at']


# ============ ADDRESS SERIALIZERS ============
class SavedAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedAddress
        fields = '__all__'
        read_only_fields = ['address_id']


# ============ CORPORATE PROFILE SERIALIZERS ============
class CorporateProfileSerializer(serializers.ModelSerializer):
    user_details = UserSerializer(source='user', read_only=True)

    class Meta:
        model = CorporateProfile
        fields = '__all__'
        read_only_fields = ['corporate_id']


# ============ VEHICLE SERIALIZERS ============
class VehiclePhotoSerializer(serializers.ModelSerializer):
    photo_url = Base64ImageField(required=True)

    class Meta:
        model = VehiclePhoto
        fields = ['photo_id', 'side', 'photo_url', 'uploaded_at']
        read_only_fields = ['photo_id', 'uploaded_at']


class VehicleSerializer(serializers.ModelSerializer):
    photos = VehiclePhotoSerializer(many=True, read_only=True)
    owner_name = serializers.CharField(source='owner.full_name', read_only=True)

    class Meta:
        model = Vehicle
        fields = '__all__'
        read_only_fields = ['vehicle_id', 'owner', 'created_at', 'verification_status']


class VehicleCreateSerializer(serializers.ModelSerializer):
    photos = VehiclePhotoSerializer(many=True, required=False)

    class Meta:
        model = Vehicle
        fields = [
            'vehicle_type', 'manufacturer', 'registration_number',
            'registration_year', 'capacity_ton', 'length_ft', 'photos'
        ]

    def create(self, validated_data):
        photos_data = validated_data.pop('photos', [])
        vehicle = Vehicle.objects.create(**validated_data)

        for photo_data in photos_data:
            VehiclePhoto.objects.create(vehicle=vehicle, **photo_data)

        return vehicle


# ============ VEHICLE SCHEDULE SERIALIZERS ============
class VehicleScheduleSerializer(serializers.ModelSerializer):
    vehicle_details = VehicleSerializer(source='vehicle', read_only=True)

    class Meta:
        model = VehicleSchedule
        fields = '__all__'
        read_only_fields = ['schedule_id']


# ============ LOAD SERIALIZERS ============
class LoadSerializer(serializers.ModelSerializer):
    consignee_name = serializers.CharField(source='consignee.full_name', read_only=True)
    bids_count = serializers.SerializerMethodField()

    class Meta:
        model = Load
        fields = '__all__'
        read_only_fields = ['load_id', 'consignee', 'status', 'created_at']

    def get_bids_count(self, obj):
        return obj.bids.count()


class LoadCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Load
        fields = [
            'pickup_address', 'pickup_lat', 'pickup_lng',
            'drop_address', 'drop_lat', 'drop_lng',
            'material_type', 'weight_kg', 'required_vehicle_type',
            'pickup_date', 'is_fragile', 'special_instructions',
            'trip_mode', 'booking_type', 'budget_price'
        ]

    def validate_pickup_date(self, value):
        if value < timezone.now():
            raise serializers.ValidationError("Pickup date cannot be in the past")
        return value


# ============ BID SERIALIZERS ============
class BidSerializer(serializers.ModelSerializer):
    transporter_name = serializers.CharField(source='transporter.full_name', read_only=True)
    vehicle_details = serializers.SerializerMethodField()

    class Meta:
        model = Bid
        fields = '__all__'
        read_only_fields = ['bid_id', 'transporter', 'bid_status', 'created_at']

    def get_vehicle_details(self, obj):
        return {
            'registration_number': obj.vehicle.registration_number,
            'vehicle_type': obj.vehicle.vehicle_type,
            'capacity_ton': obj.vehicle.capacity_ton
        }


class BidCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bid
        fields = ['load', 'vehicle', 'bid_amount', 'bid_message']

    def validate(self, data):
        load = data['load']
        if load.status != 'open':
            raise serializers.ValidationError("This load is not accepting bids")
        return data


# ============ BOOKING SERIALIZERS ============
class BookingSerializer(serializers.ModelSerializer):
    consignee_name = serializers.CharField(source='consignee.full_name', read_only=True)
    transporter_name = serializers.CharField(source='transporter.full_name', read_only=True)
    vehicle_number = serializers.CharField(source='vehicle.registration_number', read_only=True)

    class Meta:
        model = Booking
        fields = '__all__'
        read_only_fields = ['booking_id', 'created_at']


class BookingUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ['booking_status', 'driver', 'eway_bill_no', 'invoice_url', 'bilty_url']


# ============ TRACKING SERIALIZERS ============
class TrackingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShipmentTracking
        fields = ['tracking_id', 'latitude', 'longitude', 'current_location_text', 'timestamp']
        read_only_fields = ['tracking_id', 'timestamp']


class TrackingCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShipmentTracking
        fields = ['booking', 'latitude', 'longitude', 'current_location_text']


# ============ WALLET SERIALIZERS ============
class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['wallet_id', 'balance', 'currency', 'updated_at']
        read_only_fields = ['wallet_id', 'balance', 'updated_at']


class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = '__all__'
        read_only_fields = ['transaction_id', 'created_at']


# ============ PAYMENT SERIALIZERS ============
class PaymentSerializer(serializers.ModelSerializer):
    payer_name = serializers.CharField(source='payer.full_name', read_only=True)
    payee_name = serializers.CharField(source='payee.full_name', read_only=True)

    class Meta:
        model = Payment
        fields = '__all__'
        read_only_fields = ['payment_id', 'created_at', 'released_at']


# ============ RATING SERIALIZERS ============
class RatingSerializer(serializers.ModelSerializer):
    reviewer_name = serializers.CharField(source='reviewer.full_name', read_only=True)
    reviewee_name = serializers.CharField(source='reviewee.full_name', read_only=True)

    class Meta:
        model = Rating
        fields = '__all__'
        read_only_fields = ['rating_id', 'reviewer', 'created_at']


class RatingCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rating
        fields = ['booking', 'reviewee', 'score', 'comment']

    def validate_score(self, value):
        if value < 1 or value > 5:
            raise serializers.ValidationError("Score must be between 1 and 5")
        return value


# ============ DISPUTE SERIALIZERS ============
class DisputeSerializer(serializers.ModelSerializer):
    raised_by_name = serializers.CharField(source='raised_by.full_name', read_only=True)

    class Meta:
        model = Dispute
        fields = '__all__'
        read_only_fields = ['dispute_id', 'created_at']


class DisputeCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dispute
        fields = ['booking', 'reason_category', 'description', 'evidence_url']


# ============ NOTIFICATION SERIALIZERS ============
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'
        read_only_fields = ['notification_id', 'created_at']


# ============ ADMIN LOG SERIALIZERS ============
class AdminLogSerializer(serializers.ModelSerializer):
    admin_name = serializers.CharField(source='admin_user.full_name', read_only=True)

    class Meta:
        model = AdminLog
        fields = '__all__'
        read_only_fields = ['log_id', 'created_at']