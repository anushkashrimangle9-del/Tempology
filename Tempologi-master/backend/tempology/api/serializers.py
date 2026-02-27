from rest_framework import serializers
from .models import *
from django.utils import timezone
from datetime import timedelta
import random
import base64
from django.core.files.base import ContentFile
import uuid
import six
import binascii
import imghdr
from decimal import Decimal
from .pricing_calculator import PricingCalculator


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
            'status', 'is_verified', 'profile_image_url', 'created_at',
            'is_staff', 'is_superuser', 'last_login', 'plan_type',
            'rating', 'total_trips', 'visibility_score', 'annual_turnover'
        ]
        read_only_fields = ['user_id', 'is_verified', 'created_at', 'is_staff',
                            'is_superuser', 'last_login', 'rating', 'visibility_score']


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


# ============ REGISTRATION SERIALIZERS ============
class RegistrationInitSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=20, min_length=10)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)
    password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({"email": "User with this email already exists"})

        if User.objects.filter(phone_number=data['phone_number']).exists():
            raise serializers.ValidationError({"phone_number": "User with this phone number already exists"})

        return data


class VerifyBothOTPsAndRegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=20, min_length=10)
    email_otp = serializers.CharField(max_length=6)
    phone_otp = serializers.CharField(max_length=6)
    full_name = serializers.CharField(max_length=100)
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)
    password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        email = data.get('email')
        phone = data.get('phone_number')
        email_otp = data.get('email_otp')
        phone_otp = data.get('phone_otp')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "User with this email already exists"})

        if User.objects.filter(phone_number=phone).exists():
            raise serializers.ValidationError({"phone_number": "User with this phone number already exists"})

        try:
            email_otp_obj = OTP.objects.filter(
                email=email,
                otp_type='email_registration',
                otp=email_otp,
                is_used=False,
                is_verified=False,
                expires_at__gt=timezone.now()
            ).latest('created_at')
            data['email_otp_instance'] = email_otp_obj
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"email_otp": "Invalid or expired email OTP"})

        try:
            phone_otp_obj = OTP.objects.filter(
                phone_number=phone,
                otp_type='phone_registration',
                otp=phone_otp,
                is_used=False,
                is_verified=False,
                expires_at__gt=timezone.now()
            ).latest('created_at')
            data['phone_otp_instance'] = phone_otp_obj
        except OTP.DoesNotExist:
            raise serializers.ValidationError({"phone_otp": "Invalid or expired phone OTP"})

        return data


class SendOTPSerializer(serializers.Serializer):
    contact = serializers.CharField(max_length=100)
    contact_type = serializers.ChoiceField(choices=['email', 'phone'])
    otp_type = serializers.ChoiceField(choices=['email_registration', 'phone_registration', 'password_reset'])

    def validate(self, data):
        contact = data.get('contact')
        contact_type = data.get('contact_type')
        otp_type = data.get('otp_type')

        if contact_type == 'email':
            if '@' not in contact or '.' not in contact:
                raise serializers.ValidationError({"contact": "Invalid email format"})

            if otp_type == 'email_registration':
                if User.objects.filter(email=contact).exists():
                    raise serializers.ValidationError({"contact": "Email already registered"})

        elif contact_type == 'phone':
            if not contact.isdigit() or len(contact) < 10 or len(contact) > 15:
                raise serializers.ValidationError({"contact": "Invalid phone number format"})

            if otp_type == 'phone_registration':
                if User.objects.filter(phone_number=contact).exists():
                    raise serializers.ValidationError({"contact": "Phone number already registered"})

        return data


# ============ LOGIN SERIALIZERS ============
class EmailLoginSerializer(serializers.Serializer):
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

        if user.role != 'admin' and not user.is_verified:
            raise serializers.ValidationError("Account not verified. Please complete registration first.")

        data['user'] = user
        return data


# ============ PASSWORD MANAGEMENT SERIALIZERS ============
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        email = data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email")

        if not user.is_active or user.status != 'active':
            raise serializers.ValidationError("Account is not active. Cannot reset password.")

        data['user'] = user
        return data


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, min_length=6)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        email = data.get('email')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")

        if not user.is_active or user.status != 'active':
            raise serializers.ValidationError("Account is not active. Cannot reset password.")

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


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True, min_length=6)
    confirm_password = serializers.CharField(write_only=True, required=True, min_length=6)

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        if len(data['new_password']) < 6:
            raise serializers.ValidationError({"new_password": "Password must be at least 6 characters long"})

        return data


# ============ TOKEN SERIALIZERS ============
class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True)


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)


# ============ VEHICLE CATEGORY SERIALIZERS ============
class VehicleCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = VehicleCategory
        fields = '__all__'
        read_only_fields = ['category_id', 'created_at', 'updated_at']


class PricingSlabSerializer(serializers.ModelSerializer):
    vehicle_category_name = serializers.CharField(source='vehicle_category.name', read_only=True)

    class Meta:
        model = PricingSlab
        fields = '__all__'
        read_only_fields = ['slab_id', 'created_at', 'updated_at']


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
    requests_count = serializers.SerializerMethodField()
    required_vehicle_category_details = VehicleCategorySerializer(source='required_vehicle_category', read_only=True)

    class Meta:
        model = Load
        fields = '__all__'
        read_only_fields = ['load_id', 'consignee', 'status', 'created_at', 'distance_km', 'price_breakdown']

    def get_requests_count(self, obj):
        return obj.requests.count()


class LoadCreateWithPriceSerializer(serializers.ModelSerializer):
    manual_price = serializers.DecimalField(
        max_digits=15, decimal_places=2,
        required=False, write_only=True,
        help_text="Manually set price (overrides auto-calculation)"
    )
    estimated_price = serializers.DecimalField(
        max_digits=15, decimal_places=2,
        read_only=True
    )
    price_breakdown = serializers.JSONField(read_only=True)

    class Meta:
        model = Load
        fields = [
            'pickup_address', 'pickup_lat', 'pickup_lng',
            'drop_address', 'drop_lat', 'drop_lng',
            'material_type', 'weight_kg', 'required_vehicle_category',
            'pickup_date', 'is_fragile', 'special_instructions',
            'trip_mode', 'booking_type', 'trip_type',
            'manual_price', 'estimated_price', 'price_breakdown',
            'is_deliverable'
        ]
        extra_kwargs = {
            'pickup_lat': {'required': True},
            'pickup_lng': {'required': True},
            'drop_lat': {'required': True},
            'drop_lng': {'required': True},
            'required_vehicle_category': {'required': True},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calculated_price = None

    def validate(self, data):
        # Calculate distance
        distance = PricingCalculator.calculate_distance(
            data.get('pickup_lat'), data.get('pickup_lng'),
            data.get('drop_lat'), data.get('drop_lng')
        )

        if not distance:
            raise serializers.ValidationError(
                "Could not calculate distance. Please ensure valid coordinates."
            )

        # Store distance
        data['distance_km'] = Decimal(str(distance))

        # Check deliverability
        if distance < 1:
            data['is_deliverable'] = False
            raise serializers.ValidationError(
                "Distance too short for delivery. Minimum 1 km required."
            )
        else:
            data['is_deliverable'] = True

        # Auto-calculate price if not manually provided
        if 'manual_price' not in data or not data['manual_price']:
            price_details = self.calculate_estimated_price(data)
            data['budget_price'] = Decimal(str(price_details['total_price']))
            data['is_price_auto_calculated'] = True
            data['price_breakdown'] = price_details
            self.calculated_price = price_details
        else:
            data['budget_price'] = data['manual_price']
            data['is_price_auto_calculated'] = False
            data['price_breakdown'] = {'manual_price': float(data['manual_price'])}

        return data

    def calculate_estimated_price(self, data):
        """Calculate estimated price based on vehicle category"""

        class DummyVehicle:
            def __init__(self, vehicle_type, capacity_ton, length_ft):
                self.vehicle_type = vehicle_type
                self.capacity_ton = capacity_ton
                self.length_ft = length_ft

        class DummyLoad:
            def __init__(self, data):
                self.pickup_lat = data.get('pickup_lat')
                self.pickup_lng = data.get('pickup_lng')
                self.drop_lat = data.get('drop_lat')
                self.drop_lng = data.get('drop_lng')
                self.pickup_address = data.get('pickup_address', '')
                self.weight_kg = data.get('weight_kg', 1000)
                self.trip_type = data.get('trip_type', 'one_way')
                self.trip_mode = data.get('trip_mode', 'full_truck')

        vehicle_category = data['required_vehicle_category']

        dummy_vehicle = DummyVehicle(
            vehicle_category.vehicle_type,
            vehicle_category.capacity_ton,
            vehicle_category.length_ft
        )

        dummy_load = DummyLoad(data)

        try:
            price_details = PricingCalculator.calculate_price(dummy_load, dummy_vehicle)
            return price_details
        except Exception as e:
            distance = data['distance_km']
            weight_kg = float(data['weight_kg'])
            rate_per_km = float(vehicle_category.base_rate_per_km)

            base_price = float(distance) * rate_per_km
            total_price = base_price

            return {
                'distance_km': float(distance),
                'base_price': base_price,
                'total_price': total_price,
                'calculation_method': 'fallback',
                'error': str(e)
            }

    def create(self, validated_data):
        validated_data.pop('manual_price', None)
        load = Load.objects.create(**validated_data)
        return load


class LoadPriceEstimateSerializer(serializers.Serializer):
    """Serializer for price estimation only"""
    pickup_lat = serializers.DecimalField(max_digits=10, decimal_places=8)
    pickup_lng = serializers.DecimalField(max_digits=10, decimal_places=8)
    drop_lat = serializers.DecimalField(max_digits=10, decimal_places=8)
    drop_lng = serializers.DecimalField(max_digits=10, decimal_places=8)
    weight_kg = serializers.DecimalField(max_digits=10, decimal_places=2)
    vehicle_category_id = serializers.IntegerField()
    pickup_address = serializers.CharField(required=False, allow_blank=True)
    trip_type = serializers.ChoiceField(choices=Load.TRIP_TYPES, default='one_way')
    trip_mode = serializers.ChoiceField(choices=Load.TRIP_MODES, default='full_truck')

    def validate(self, data):
        try:
            vehicle_category = VehicleCategory.objects.get(
                category_id=data['vehicle_category_id'],
                is_active=True
            )
        except VehicleCategory.DoesNotExist:
            raise serializers.ValidationError(
                {"vehicle_category_id": "Invalid vehicle category"}
            )

        class DummyLoad:
            def __init__(self, data):
                self.pickup_lat = data.get('pickup_lat')
                self.pickup_lng = data.get('pickup_lng')
                self.drop_lat = data.get('drop_lat')
                self.drop_lng = data.get('drop_lng')
                self.pickup_address = data.get('pickup_address', '')
                self.weight_kg = data.get('weight_kg')
                self.trip_type = data.get('trip_type', 'one_way')
                self.trip_mode = data.get('trip_mode', 'full_truck')

        class DummyVehicle:
            def __init__(self, category):
                self.vehicle_type = category.vehicle_type
                self.capacity_ton = category.capacity_ton
                self.length_ft = category.length_ft

        dummy_load = DummyLoad(data)
        dummy_vehicle = DummyVehicle(vehicle_category)

        price_details = PricingCalculator.calculate_price(dummy_load, dummy_vehicle)
        data['price_details'] = price_details

        return data


# ============ LOAD REQUEST SERIALIZERS ============
class LoadRequestSerializer(serializers.ModelSerializer):
    requester_name = serializers.CharField(source='requester.full_name', read_only=True)
    load_details = LoadSerializer(source='load', read_only=True)
    vehicle_details = serializers.SerializerMethodField()

    class Meta:
        model = LoadRequest
        fields = [
            'request_id', 'load', 'load_details', 'requester', 'requester_name',
            'vehicle', 'vehicle_details', 'distance_km', 'base_price',
            'weight_factor', 'traffic_multiplier', 'fuel_surcharge', 'total_price',
            'message', 'status', 'expires_at', 'created_at', 'responded_at'
        ]
        read_only_fields = [
            'request_id', 'requester', 'distance_km', 'base_price',
            'weight_factor', 'traffic_multiplier', 'fuel_surcharge', 'total_price',
            'status', 'created_at', 'responded_at'
        ]

    def get_vehicle_details(self, obj):
        return {
            'vehicle_id': obj.vehicle.vehicle_id,
            'registration_number': obj.vehicle.registration_number,
            'vehicle_type': obj.vehicle.get_vehicle_type_display(),
            'capacity_ton': float(obj.vehicle.capacity_ton)
        }


class LoadRequestCreateSerializer(serializers.Serializer):
    load_id = serializers.IntegerField()
    vehicle_id = serializers.IntegerField()
    message = serializers.CharField(required=False, allow_blank=True)
    expires_in_hours = serializers.IntegerField(default=24, min_value=1, max_value=168)

    def validate(self, data):
        user = self.context['request'].user

        try:
            load = Load.objects.get(load_id=data['load_id'])
        except Load.DoesNotExist:
            raise serializers.ValidationError({"load_id": "Load not found"})

        if load.status != 'open':
            raise serializers.ValidationError({"load_id": "This load is no longer accepting requests"})

        if LoadRequest.objects.filter(load=load, requester=user, status='pending').exists():
            raise serializers.ValidationError({"load_id": "You already have a pending request for this load"})

        data['load'] = load

        try:
            vehicle = Vehicle.objects.get(vehicle_id=data['vehicle_id'])
        except Vehicle.DoesNotExist:
            raise serializers.ValidationError({"vehicle_id": "Vehicle not found"})

        if vehicle.owner != user:
            raise serializers.ValidationError({"vehicle_id": "Vehicle does not belong to you"})

        if vehicle.verification_status != 'verified':
            raise serializers.ValidationError({"vehicle_id": "Vehicle is not verified"})

        data['vehicle'] = vehicle

        return data

    def create(self, validated_data):
        user = self.context['request'].user
        load = validated_data['load']
        vehicle = validated_data['vehicle']

        price_details = PricingCalculator.calculate_price(load, vehicle)

        expires_at = timezone.now() + timedelta(hours=validated_data.get('expires_in_hours', 24))

        load_request = LoadRequest.objects.create(
            load=load,
            requester=user,
            vehicle=vehicle,
            distance_km=Decimal(str(price_details['distance_km'])),
            base_price=Decimal(str(price_details['base_price'])),
            weight_factor=Decimal('1.0'),
            traffic_multiplier=Decimal('1.0'),
            fuel_surcharge=Decimal('0.0'),
            total_price=Decimal(str(price_details['total_price'])),
            message=validated_data.get('message', ''),
            expires_at=expires_at
        )

        return load_request


# ============ TRIP SERIALIZERS ============
class TripLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = TripLocation
        fields = ['location_id', 'latitude', 'longitude', 'location_address', 'timestamp']


class TripSerializer(serializers.ModelSerializer):
    vehicle_details = serializers.SerializerMethodField()
    driver_name = serializers.CharField(source='driver.full_name', read_only=True, allow_null=True)
    current_location_details = serializers.SerializerMethodField()
    return_trip_offers = serializers.SerializerMethodField()
    booking_details = serializers.SerializerMethodField()

    class Meta:
        model = Trip
        fields = '__all__'
        read_only_fields = ['trip_id', 'created_at', 'updated_at']

    def get_vehicle_details(self, obj):
        return {
            'registration_number': obj.vehicle.registration_number,
            'vehicle_type': obj.vehicle.get_vehicle_type_display(),
            'capacity_ton': float(obj.vehicle.capacity_ton)
        }

    def get_current_location_details(self, obj):
        if obj.current_lat and obj.current_lng:
            return {
                'lat': float(obj.current_lat),
                'lng': float(obj.current_lng),
                'address': obj.current_location
            }
        return None

    def get_return_trip_offers(self, obj):
        if obj.is_return_trip_available:
            offers = ReturnTripOffer.objects.filter(original_trip=obj, is_active=True)
            return ReturnTripOfferSerializer(offers, many=True).data
        return []

    def get_booking_details(self, obj):
        if obj.booking:
            return {
                'booking_id': obj.booking.booking_id,
                'status': obj.booking.booking_status,
                'load_id': obj.booking.load.load_id if obj.booking.load else None
            }
        return None


class ReturnTripOfferSerializer(serializers.ModelSerializer):
    original_trip_details = TripSerializer(source='original_trip', read_only=True)

    class Meta:
        model = ReturnTripOffer
        fields = '__all__'
        read_only_fields = ['offer_id', 'created_at']


# ============ BOOKING SERIALIZERS ============
class BookingSerializer(serializers.ModelSerializer):
    consignee_name = serializers.CharField(source='consignee.full_name', read_only=True)
    transporter_name = serializers.CharField(source='transporter.full_name', read_only=True)
    vehicle_number = serializers.CharField(source='vehicle.registration_number', read_only=True)
    driver_name = serializers.CharField(source='driver.full_name', read_only=True, allow_null=True)
    extra_charges = serializers.SerializerMethodField()
    penalties = serializers.SerializerMethodField()
    trip_details = TripSerializer(source='trip', read_only=True)
    load_details = LoadSerializer(source='load', read_only=True)

    class Meta:
        model = Booking
        fields = '__all__'
        read_only_fields = ['booking_id', 'created_at']

    def get_extra_charges(self, obj):
        charges = ExtraCharge.objects.filter(booking=obj)
        return ExtraChargeSerializer(charges, many=True).data

    def get_penalties(self, obj):
        penalties = Penalty.objects.filter(booking=obj)
        return PenaltySerializer(penalties, many=True).data


class BookingUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ['booking_status', 'driver', 'eway_bill_no', 'invoice_url', 'bilty_url',
                  'delivery_time_commitment', 'actual_delivery_time']


# ============ EXTRA CHARGE SERIALIZERS ============
class ExtraChargeSerializer(serializers.ModelSerializer):
    charge_type_display = serializers.CharField(source='get_charge_type_display', read_only=True)
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True, allow_null=True)

    class Meta:
        model = ExtraCharge
        fields = '__all__'
        read_only_fields = ['charge_id', 'created_at']


# ============ PENALTY SERIALIZERS ============
class PenaltySerializer(serializers.ModelSerializer):
    penalty_type_display = serializers.CharField(source='get_penalty_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    applied_to_name = serializers.CharField(source='applied_to.full_name', read_only=True)
    applied_by_name = serializers.CharField(source='applied_by.full_name', read_only=True, allow_null=True)
    booking_details = serializers.SerializerMethodField()

    class Meta:
        model = Penalty
        fields = '__all__'
        read_only_fields = ['penalty_id', 'created_at', 'resolved_at']

    def get_booking_details(self, obj):
        if obj.booking:
            return {
                'booking_id': obj.booking.booking_id,
                'total_amount': float(obj.booking.total_amount)
            }
        return None


# ============ WALLET SERIALIZERS ============
class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['wallet_id', 'user_id', 'balance', 'reward_points', 'cashback_balance',
                  'currency', 'consumption_percentage', 'updated_at']
        read_only_fields = ['wallet_id', 'balance', 'reward_points', 'cashback_balance', 'updated_at']


class WalletTransactionSerializer(serializers.ModelSerializer):
    transaction_type_display = serializers.CharField(source='get_transaction_type_display', read_only=True)
    reference_type_display = serializers.CharField(source='get_reference_type_display', read_only=True)

    class Meta:
        model = WalletTransaction
        fields = '__all__'
        read_only_fields = ['transaction_id', 'created_at']


class WalletConsumptionSerializer(serializers.Serializer):
    """Calculate wallet consumption for a trip"""
    booking_id = serializers.IntegerField()
    wallet_id = serializers.IntegerField()

    def validate(self, data):
        try:
            booking = Booking.objects.get(booking_id=data['booking_id'])
        except Booking.DoesNotExist:
            raise serializers.ValidationError({"booking_id": "Booking not found"})

        try:
            wallet = Wallet.objects.get(wallet_id=data['wallet_id'])
        except Wallet.DoesNotExist:
            raise serializers.ValidationError({"wallet_id": "Wallet not found"})

        consumption = PricingCalculator.calculate_wallet_consumption(
            float(booking.total_amount),
            float(wallet.balance)
        )

        data['booking'] = booking
        data['wallet'] = wallet
        data['consumption'] = consumption
        return data


# ============ PAYMENT SERIALIZERS ============
class PaymentSerializer(serializers.ModelSerializer):
    payer_name = serializers.CharField(source='payer.full_name', read_only=True)
    payee_name = serializers.CharField(source='payee.full_name', read_only=True)
    payment_status_display = serializers.CharField(source='get_payment_status_display', read_only=True)
    payment_gateway_display = serializers.CharField(source='get_payment_gateway_display', read_only=True)

    class Meta:
        model = Payment
        fields = '__all__'
        read_only_fields = ['payment_id', 'created_at', 'released_at']


# ============ RATING SERIALIZERS ============
class RatingSerializer(serializers.ModelSerializer):
    reviewer_name = serializers.CharField(source='reviewer.full_name', read_only=True)
    reviewee_name = serializers.CharField(source='reviewee.full_name', read_only=True)
    booking_details = serializers.SerializerMethodField()

    class Meta:
        model = Rating
        fields = '__all__'
        read_only_fields = ['rating_id', 'reviewer', 'created_at']

    def get_booking_details(self, obj):
        return {
            'booking_id': obj.booking.booking_id,
            'load_id': obj.booking.load.load_id if obj.booking.load else None
        }


class RatingCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rating
        fields = ['booking', 'reviewee', 'score', 'comment']

    def validate_score(self, value):
        if value < 1 or value > 5:
            raise serializers.ValidationError("Score must be between 1 and 5")
        return value

    def validate(self, data):
        try:
            booking = Booking.objects.get(booking_id=data['booking'].booking_id)
            if booking.booking_status != 'completed':
                raise serializers.ValidationError(
                    "You can only rate completed bookings"
                )
        except Booking.DoesNotExist:
            pass
        return data


# ============ DISPUTE SERIALIZERS ============
class DisputeSerializer(serializers.ModelSerializer):
    raised_by_name = serializers.CharField(source='raised_by.full_name', read_only=True)
    reason_category_display = serializers.CharField(source='get_reason_category_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    booking_details = serializers.SerializerMethodField()

    class Meta:
        model = Dispute
        fields = '__all__'
        read_only_fields = ['dispute_id', 'created_at']

    def get_booking_details(self, obj):
        return {
            'booking_id': obj.booking.booking_id,
            'total_amount': float(obj.booking.total_amount)
        }


class DisputeCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dispute
        fields = ['booking', 'reason_category', 'description', 'evidence_url']


# ============ FESTIVAL GIFT SERIALIZERS ============
class FestivalGiftSerializer(serializers.ModelSerializer):
    festival_display = serializers.CharField(source='get_festival_display', read_only=True)
    gift_type_display = serializers.CharField(source='get_gift_type_display', read_only=True)
    recipient_name = serializers.CharField(source='recipient.full_name', read_only=True)
    recipient_rating = serializers.DecimalField(source='recipient.rating', max_digits=3, decimal_places=2,
                                                read_only=True)
    recipient_turnover = serializers.DecimalField(source='recipient.annual_turnover', max_digits=15, decimal_places=2,
                                                  read_only=True)
    created_by_name = serializers.CharField(source='created_by.full_name', read_only=True, allow_null=True)

    class Meta:
        model = FestivalGift
        fields = '__all__'
        read_only_fields = ['gift_id', 'created_at', 'delivered_at']


# ============ NOTIFICATION SERIALIZERS ============
class NotificationSerializer(serializers.ModelSerializer):
    type_display = serializers.CharField(source='get_type_display', read_only=True)

    class Meta:
        model = Notification
        fields = '__all__'
        read_only_fields = ['notification_id', 'created_at']


# ============ KYC DOCUMENT SERIALIZERS ============
class KYCDocumentSerializer(serializers.ModelSerializer):
    file_url = Base64ImageField(required=True)
    document_type_display = serializers.CharField(source='get_document_type_display', read_only=True)
    verification_status_display = serializers.CharField(source='get_verification_status_display', read_only=True)
    user_name = serializers.CharField(source='user.full_name', read_only=True)

    class Meta:
        model = KYCDocument
        fields = [
            'doc_id', 'user', 'user_name', 'document_type', 'document_type_display',
            'document_number', 'file_url', 'expiry_date', 'verification_status',
            'verification_status_display', 'rejection_reason', 'uploaded_at'
        ]
        read_only_fields = ['doc_id', 'verification_status', 'rejection_reason', 'uploaded_at']


# ============ ADDRESS SERIALIZERS ============
class SavedAddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedAddress
        fields = '__all__'
        read_only_fields = ['address_id']
        extra_kwargs = {'user': {'required': False}}


# ============ CORPORATE PROFILE SERIALIZERS ============
class CorporateProfileSerializer(serializers.ModelSerializer):
    user_details = UserSerializer(source='user', read_only=True)

    class Meta:
        model = CorporateProfile
        fields = '__all__'
        read_only_fields = ['corporate_id']


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


# ============ ADMIN LOG SERIALIZERS ============
class AdminLogSerializer(serializers.ModelSerializer):
    admin_name = serializers.CharField(source='admin_user.full_name', read_only=True)

    class Meta:
        model = AdminLog
        fields = '__all__'
        read_only_fields = ['log_id', 'created_at']