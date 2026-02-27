from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.db import transaction
from django.db.models import Q, Count, Sum, Avg
from django.utils import timezone
from datetime import timedelta
import random
import uuid
from decimal import Decimal
from .models import *
from .serializers import *
from .permission import *
from .pricing_calculator import PricingCalculator


# ============ UTILITY FUNCTIONS ============
def generate_session_id():
    return str(uuid.uuid4())


def get_role_dashboard_url(role):
    urls = {
        'consignee': '/consignee/dashboard/',
        'truck_owner': '/owner/dashboard/',
        'transporter': '/transporter/dashboard/',
        'corporate': '/corporate/dashboard/',
        'admin': '/admin/dashboard/',
        'driver': '/driver/dashboard/',
    }
    return urls.get(role, '/')


def create_notification(user, title, message, notification_type='system'):
    try:
        Notification.objects.create(
            user=user,
            title=title,
            message=message,
            type=notification_type
        )
    except Exception as e:
        print(f"Notification creation error: {e}")


def generate_otp():
    return str(random.randint(100000, 999999))


def send_otp(contact, contact_type, otp, otp_type):
    if contact_type == 'email':
        print(f"Email OTP {otp} sent to {contact} for {otp_type}")
        # TODO: Integrate with actual email service
        return True
    else:
        print(f"SMS OTP {otp} sent to {contact} for {otp_type}")
        # TODO: Integrate with actual SMS service
        return True


def notify_nearby_transporters(load):
    """Notify nearby transporters about new load"""
    try:
        if load.pickup_lat and load.pickup_lng:
            transporters = User.objects.filter(
                Q(role='transporter') | Q(role='truck_owner'),
                is_active=True, status='active'
            )[:50]

            for transporter in transporters:
                create_notification(
                    transporter, 'New Load Available',
                    f'New {load.get_trip_mode_display()} load available from {load.pickup_address[:50]}... Weight: {load.weight_kg}kg',
                    'load'
                )
    except Exception as e:
        print(f"Error notifying transporters: {e}")


# ============ REGISTRATION & AUTH VIEWS ============
@api_view(['POST'])
@permission_classes([AllowAny])
def register_init_view(request):
    """Initialize registration - send OTPs"""
    try:
        serializer = RegistrationInitSerializer(data=request.data)

        if serializer.is_valid():
            validated_data = serializer.validated_data
            email = validated_data['email']
            phone = validated_data['phone_number']

            email_otp = generate_otp()
            phone_otp = generate_otp()

            # Invalidate old OTPs
            OTP.objects.filter(
                email=email, otp_type='email_registration',
                is_used=False, is_verified=False
            ).update(is_used=True)

            OTP.objects.filter(
                phone_number=phone, otp_type='phone_registration',
                is_used=False, is_verified=False
            ).update(is_used=True)

            # Create new OTPs
            OTP.objects.create(
                email=email, otp=email_otp, otp_type='email_registration',
                expires_at=timezone.now() + timedelta(minutes=10)
            )

            OTP.objects.create(
                phone_number=phone, otp=phone_otp, otp_type='phone_registration',
                expires_at=timezone.now() + timedelta(minutes=10)
            )

            send_otp(email, 'email', email_otp, 'email_registration')
            send_otp(phone, 'phone', phone_otp, 'phone_registration')

            response_data = {
                'success': True,
                'message': 'OTPs sent to both email and phone.',
                'data': {'email': email, 'phone_number': phone, 'expires_in': 600}
            }

            if getattr(settings, 'DEBUG', False):
                response_data['data']['test_otps'] = {
                    'email_otp': email_otp, 'phone_otp': phone_otp
                }

            return Response(response_data)

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_both_otps_and_register_view(request):
    """Verify OTPs and complete registration"""
    try:
        serializer = VerifyBothOTPsAndRegisterSerializer(data=request.data)

        if serializer.is_valid():
            with transaction.atomic():
                email = serializer.validated_data['email']
                phone = serializer.validated_data['phone_number']
                email_otp_obj = serializer.validated_data['email_otp_instance']
                phone_otp_obj = serializer.validated_data['phone_otp_instance']

                email_otp_obj.is_verified = True
                email_otp_obj.is_used = True
                email_otp_obj.save()

                phone_otp_obj.is_verified = True
                phone_otp_obj.is_used = True
                phone_otp_obj.save()

                role = serializer.validated_data['role']
                is_staff = (role == 'admin')
                is_superuser = (role == 'admin')

                user = User.objects.create_user(
                    phone_number=phone,
                    full_name=serializer.validated_data['full_name'],
                    role=role,
                    email=email,
                    password=serializer.validated_data['password'],
                    is_verified=True,
                    is_staff=is_staff,
                    is_superuser=is_superuser
                )

                # Create wallet
                Wallet.objects.get_or_create(user=user)

                # Generate tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                refresh['role'] = user.role
                refresh['email'] = user.email
                refresh['name'] = user.full_name

                create_notification(
                    user, 'Welcome to TempoLogi',
                    f'Welcome {user.full_name}! Your account has been created successfully.',
                    'system'
                )

                return Response({
                    'success': True,
                    'message': 'Registration completed successfully',
                    'data': {
                        'user': UserSerializer(user, context={'request': request}).data,
                        'tokens': {
                            'access': access_token,
                            'refresh': str(refresh),
                            'expires_in': 3600
                        },
                        'redirect_url': get_role_dashboard_url(user.role)
                    }
                }, status=status.HTTP_201_CREATED)

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def send_registration_otp_view(request):
    """Send OTP for email or phone individually"""
    try:
        serializer = SendOTPSerializer(data=request.data)

        if serializer.is_valid():
            contact = serializer.validated_data['contact']
            contact_type = serializer.validated_data['contact_type']
            otp_type = serializer.validated_data['otp_type']

            otp = generate_otp()

            filter_kwargs = {
                'otp_type': otp_type,
                'is_used': False,
                'is_verified': False
            }

            if contact_type == 'email':
                filter_kwargs['email'] = contact
            else:
                filter_kwargs['phone_number'] = contact

            OTP.objects.filter(**filter_kwargs).update(is_used=True)

            otp_kwargs = {
                'otp': otp,
                'otp_type': otp_type,
                'expires_at': timezone.now() + timedelta(minutes=10)
            }

            if contact_type == 'email':
                otp_kwargs['email'] = contact
            else:
                otp_kwargs['phone_number'] = contact

            OTP.objects.create(**otp_kwargs)

            send_otp(contact, contact_type, otp, otp_type)

            response_data = {
                'success': True,
                'message': f'OTP sent successfully to {contact_type}',
                'data': {
                    'contact': contact,
                    'contact_type': contact_type,
                    'otp_type': otp_type,
                    'expires_in': 600
                }
            }

            if getattr(settings, 'DEBUG', False):
                response_data['data']['test_otp'] = otp

            return Response(response_data)

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_email_view(request):
    """Login with email and password"""
    try:
        serializer = EmailLoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            if user.role != 'admin' and not user.is_verified:
                return Response({
                    'success': False,
                    'message': 'Account not verified. Please complete registration first.'
                }, status=status.HTTP_400_BAD_REQUEST)

            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            refresh['role'] = user.role
            refresh['email'] = user.email
            refresh['name'] = user.full_name

            create_notification(
                user, 'New Login Detected',
                f'New login to your account at {timezone.now().strftime("%Y-%m-%d %H:%M")}',
                'security'
            )

            return Response({
                'success': True,
                'message': 'Login successful',
                'data': {
                    'user': UserSerializer(user, context={'request': request}).data,
                    'tokens': {
                        'access': access_token,
                        'refresh': str(refresh),
                        'expires_in': 3600
                    },
                    'redirect_url': get_role_dashboard_url(user.role)
                }
            })

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_view(request):
    """Send OTP to email for password reset"""
    try:
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            email = user.email

            otp = generate_otp()

            OTP.objects.filter(
                email=email,
                otp_type='password_reset',
                is_used=False
            ).update(is_used=True)

            OTP.objects.create(
                email=email,
                otp=otp,
                otp_type='password_reset',
                expires_at=timezone.now() + timedelta(minutes=5)
            )

            send_otp(email, 'email', otp, 'password_reset')

            response_data = {
                'success': True,
                'message': 'OTP sent for password reset to your email',
                'data': {'email': email, 'expires_in': 300}
            }

            if getattr(settings, 'DEBUG', False):
                response_data['data']['test_otp'] = otp

            return Response(response_data)

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_view(request):
    """Reset password with OTP"""
    try:
        serializer = ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            otp_obj = serializer.validated_data['otp_instance']

            user.set_password(serializer.validated_data['new_password'])
            user.save()

            otp_obj.is_used = True
            otp_obj.save()

            create_notification(
                user,
                'Password Reset Successful',
                'Your password has been successfully reset.',
                'security'
            )

            return Response({
                'success': True,
                'message': 'Password reset successful'
            })

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    """Change password for authenticated user"""
    try:
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')

        if not all([current_password, new_password, confirm_password]):
            return Response({
                'success': False,
                'message': 'All fields are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        if not user.check_password(current_password):
            return Response({
                'success': False,
                'message': 'Current password is incorrect'
            }, status=status.HTTP_400_BAD_REQUEST)

        if new_password != confirm_password:
            return Response({
                'success': False,
                'message': 'New password and confirm password do not match'
            }, status=status.HTTP_400_BAD_REQUEST)

        if current_password == new_password:
            return Response({
                'success': False,
                'message': 'New password must be different from current password'
            }, status=status.HTTP_400_BAD_REQUEST)

        if len(new_password) < 6:
            return Response({
                'success': False,
                'message': 'Password must be at least 6 characters long'
            }, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        create_notification(
            user,
            'Password Changed',
            'Your password has been successfully changed.',
            'security'
        )

        return Response({
            'success': True,
            'message': 'Password changed successfully. Please login again with your new password.'
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout user by blacklisting refresh token"""
    try:
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()

        return Response({
            'success': True,
            'message': 'Logged out successfully'
        })
    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def refresh_token_view(request):
    """Refresh access token"""
    try:
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({
                'success': False,
                'message': 'Refresh token is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        token = RefreshToken(refresh_token)
        access_token = str(token.access_token)

        return Response({
            'success': True,
            'data': {
                'access': access_token,
                'expires_in': 3600
            }
        })
    except Exception as e:
        return Response({
            'success': False,
            'message': 'Invalid or expired refresh token'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me_view(request):
    """Get current authenticated user details"""
    try:
        serializer = UserSerializer(request.user, context={'request': request})
        return Response({
            'success': True,
            'data': serializer.data
        })
    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ PROFILE & DASHBOARD VIEWS ============
@api_view(['GET', 'PUT', 'PATCH'])
@permission_classes([IsAuthenticated, IsActiveUser])
def profile_view(request):
    """Get or update user profile"""
    try:
        if request.method == 'GET':
            serializer = UserSerializer(request.user, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = ProfileUpdateSerializer(
                request.user, data=request.data, partial=True,
                context={'request': request}
            )
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'data': UserSerializer(request.user, context={'request': request}).data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def dashboard_view(request):
    """Get dashboard summary based on user role"""
    try:
        user = request.user
        summary = {}

        if user.role in ['consignee', 'corporate']:
            loads = Load.objects.filter(consignee=user)
            bookings = Booking.objects.filter(consignee=user)

            summary = {
                'total_loads': loads.count(),
                'open_loads': loads.filter(status='open').count(),
                'active_bookings': bookings.filter(
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']
                ).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
                'pending_requests': LoadRequest.objects.filter(load__consignee=user, status='pending').count(),
            }

        elif user.role in ['truck_owner', 'transporter']:
            vehicles = Vehicle.objects.filter(owner=user)
            bookings = Booking.objects.filter(transporter=user)
            requests = LoadRequest.objects.filter(requester=user)
            trips = Trip.objects.filter(owner=user)

            summary = {
                'total_vehicles': vehicles.count(),
                'active_vehicles': vehicles.filter(is_active=True).count(),
                'pending_verifications': vehicles.filter(verification_status='pending').count(),
                'pending_requests': requests.filter(status='pending').count(),
                'accepted_requests': requests.filter(status='accepted').count(),
                'active_bookings': bookings.filter(
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']
                ).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
                'active_trips': trips.filter(status__in=['in_transit', 'boarding']).count(),
                'visibility_score': float(user.visibility_score),
                'plan_type': user.plan_type,
            }

        elif user.role == 'driver':
            bookings = Booking.objects.filter(driver=user)
            trips = Trip.objects.filter(driver=user)

            summary = {
                'active_bookings': bookings.filter(
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']
                ).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
                'current_trip': TripSerializer(trips.filter(status='in_transit').first()).data if trips.filter(
                    status='in_transit').exists() else None,
                'rating': float(user.rating),
                'total_trips': user.total_trips,
            }

        elif user.role == 'admin':
            summary = {
                'total_users': User.objects.count(),
                'total_vehicles': Vehicle.objects.count(),
                'total_loads': Load.objects.count(),
                'total_bookings': Booking.objects.count(),
                'pending_kyc': KYCDocument.objects.filter(verification_status='pending').count(),
                'pending_vehicle_verifications': Vehicle.objects.filter(verification_status='pending').count(),
                'open_disputes': Dispute.objects.filter(status__in=['open', 'investigating']).count(),
                'pending_requests': LoadRequest.objects.filter(status='pending').count(),
                'active_trips': Trip.objects.filter(status='in_transit').count(),
                'delayed_trips': Trip.objects.filter(status='delayed').count(),
                'total_penalties': Penalty.objects.filter(status='applied').aggregate(Sum('penalty_amount'))[
                                       'penalty_amount__sum'] or 0,
            }

        # Get wallet details
        try:
            wallet = Wallet.objects.get(user=user)
            summary['wallet'] = {
                'balance': float(wallet.balance),
                'reward_points': float(wallet.reward_points),
                'cashback_balance': float(wallet.cashback_balance)
            }
        except Wallet.DoesNotExist:
            summary['wallet'] = {'balance': 0, 'reward_points': 0, 'cashback_balance': 0}

        summary['unread_notifications'] = Notification.objects.filter(user=user, is_read=False).count()

        return Response({'success': True, 'data': summary})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ KYC DOCUMENT VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_kyc_documents(request):
    try:
        if request.method == 'GET':
            documents = KYCDocument.objects.filter(user=request.user)
            serializer = KYCDocumentSerializer(documents, many=True, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = KYCDocumentSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save(user=request.user)
                return Response({
                    'success': True,
                    'message': 'KYC document uploaded successfully',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated, IsActiveUser, IsDocumentOwner])
def kyc_document_detail(request, doc_id):
    try:
        document = KYCDocument.objects.get(doc_id=doc_id)

        if request.method == 'GET':
            serializer = KYCDocumentSerializer(document, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'DELETE':
            document.delete()
            return Response({
                'success': True,
                'message': 'Document deleted successfully'
            })

    except KYCDocument.DoesNotExist:
        return Response({'success': False, 'message': 'Document not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADDRESS VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_addresses(request):
    try:
        if request.method == 'GET':
            addresses = SavedAddress.objects.filter(user=request.user)
            serializer = SavedAddressSerializer(addresses, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = SavedAddressSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                return Response({
                    'success': True,
                    'message': 'Address saved successfully',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsActiveUser, IsAddressOwner])
def address_detail(request, address_id):
    try:
        address = SavedAddress.objects.get(address_id=address_id)

        if request.method == 'GET':
            serializer = SavedAddressSerializer(address)
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = SavedAddressSerializer(address, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Address updated successfully',
                    'data': serializer.data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            address.delete()
            return Response({
                'success': True,
                'message': 'Address deleted successfully'
            })

    except SavedAddress.DoesNotExist:
        return Response({'success': False, 'message': 'Address not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ CORPORATE PROFILE VIEWS ============
@api_view(['GET', 'POST', 'PUT'])
@permission_classes([IsAuthenticated, IsCorporate, IsActiveUser])
def corporate_profile(request):
    try:
        if request.method == 'GET':
            try:
                profile = CorporateProfile.objects.get(user=request.user)
                serializer = CorporateProfileSerializer(profile)
                return Response({'success': True, 'data': serializer.data})
            except CorporateProfile.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'Corporate profile not found'
                }, status=status.HTTP_404_NOT_FOUND)

        elif request.method == 'POST':
            serializer = CorporateProfileSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(user=request.user)
                return Response({
                    'success': True,
                    'message': 'Corporate profile created successfully',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            try:
                profile = CorporateProfile.objects.get(user=request.user)
                serializer = CorporateProfileSerializer(profile, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({
                        'success': True,
                        'message': 'Corporate profile updated',
                        'data': serializer.data
                    })
                return Response({'success': False, 'errors': serializer.errors},
                                status=status.HTTP_400_BAD_REQUEST)
            except CorporateProfile.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'Profile not found'
                }, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ VEHICLE VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsTruckOwnerOrTransporter, IsActiveUser])
def my_vehicles(request):
    try:
        if request.method == 'GET':
            vehicles = Vehicle.objects.filter(owner=request.user)
            serializer = VehicleSerializer(vehicles, many=True, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = VehicleCreateSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                vehicle = serializer.save(owner=request.user)
                return Response({
                    'success': True,
                    'message': 'Vehicle registered successfully',
                    'data': VehicleSerializer(vehicle, context={'request': request}).data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsActiveUser, IsVehicleOwner])
def vehicle_detail(request, vehicle_id):
    try:
        vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)

        if request.method == 'GET':
            serializer = VehicleSerializer(vehicle, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = VehicleCreateSerializer(vehicle, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Vehicle updated successfully',
                    'data': VehicleSerializer(vehicle, context={'request': request}).data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            vehicle.delete()
            return Response({
                'success': True,
                'message': 'Vehicle deleted successfully'
            })

    except Vehicle.DoesNotExist:
        return Response({'success': False, 'message': 'Vehicle not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser, IsVehicleOwner])
def vehicle_availability(request, vehicle_id):
    try:
        vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)

        if request.method == 'GET':
            schedules = VehicleSchedule.objects.filter(vehicle=vehicle, status='active')
            serializer = VehicleScheduleSerializer(schedules, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            is_available = request.data.get('is_available', True)
            vehicle.is_active = is_available
            vehicle.save()

            return Response({
                'success': True,
                'message': f'Vehicle availability updated to {"available" if is_available else "unavailable"}'
            })

    except Vehicle.DoesNotExist:
        return Response({'success': False, 'message': 'Vehicle not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ VEHICLE SCHEDULE VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsTruckOwnerOrTransporter, IsActiveUser])
def my_schedules(request):
    try:
        if request.method == 'GET':
            schedules = VehicleSchedule.objects.filter(vehicle__owner=request.user)
            serializer = VehicleScheduleSerializer(schedules, many=True, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = VehicleScheduleSerializer(data=request.data)
            if serializer.is_valid():
                vehicle_id = request.data.get('vehicle')
                try:
                    vehicle = Vehicle.objects.get(vehicle_id=vehicle_id, owner=request.user)
                except Vehicle.DoesNotExist:
                    return Response({
                        'success': False,
                        'message': 'Vehicle not found or does not belong to you'
                    }, status=status.HTTP_400_BAD_REQUEST)

                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Schedule created successfully',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsActiveUser, IsScheduleOwner])
def schedule_detail(request, schedule_id):
    try:
        schedule = VehicleSchedule.objects.get(schedule_id=schedule_id)

        if request.method == 'GET':
            serializer = VehicleScheduleSerializer(schedule, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = VehicleScheduleSerializer(schedule, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Schedule updated successfully',
                    'data': serializer.data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            schedule.delete()
            return Response({
                'success': True,
                'message': 'Schedule deleted successfully'
            })

    except VehicleSchedule.DoesNotExist:
        return Response({'success': False, 'message': 'Schedule not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsTruckOwnerOrTransporter, IsActiveUser])
def create_return_trip_schedule(request):
    """Upload schedule for empty return trips"""
    try:
        serializer = VehicleScheduleSerializer(data=request.data)
        if serializer.is_valid():
            vehicle_id = request.data.get('vehicle')
            try:
                vehicle = Vehicle.objects.get(vehicle_id=vehicle_id, owner=request.user)
            except Vehicle.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'Vehicle not found or does not belong to you'
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer.save(trip_type='return')
            return Response({
                'success': True,
                'message': 'Return trip schedule created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ LOAD VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsConsigneeOrCorporate, IsActiveUser])
def my_loads(request):
    try:
        if request.method == 'GET':
            loads = Load.objects.filter(consignee=request.user).order_by('-created_at')
            serializer = LoadSerializer(loads, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = LoadCreateWithPriceSerializer(
                data=request.data, context={'request': request}
            )

            if serializer.is_valid():
                load = serializer.save(consignee=request.user)
                notify_nearby_transporters(load)

                return Response({
                    'success': True,
                    'message': 'Load created successfully with auto-calculated price',
                    'data': LoadSerializer(load).data,
                    'price_breakdown': load.price_breakdown
                }, status=status.HTTP_201_CREATED)

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsActiveUser, IsLoadOwner])
def load_detail(request, load_id):
    try:
        load = Load.objects.get(load_id=load_id)

        if request.method == 'GET':
            serializer = LoadSerializer(load)
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            if load.status != 'open':
                return Response({
                    'success': False,
                    'message': 'Cannot update load that is not open'
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = LoadCreateWithPriceSerializer(load, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Load updated successfully',
                    'data': LoadSerializer(load).data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if load.status != 'open':
                return Response({
                    'success': False,
                    'message': 'Cannot delete load that is not open'
                }, status=status.HTTP_400_BAD_REQUEST)
            load.delete()
            return Response({'success': True, 'message': 'Load deleted successfully'})

    except Load.DoesNotExist:
        return Response({'success': False, 'message': 'Load not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsTruckOwnerOrTransporter, IsActiveUser])
def search_loads(request):
    """Search for loads matching vehicle availability"""
    try:
        loads = Load.objects.filter(status='open', pickup_date__gte=timezone.now())

        vehicle_type = request.GET.get('vehicle_type')
        if vehicle_type:
            loads = loads.filter(required_vehicle_category__vehicle_type=vehicle_type)

        min_weight = request.GET.get('min_weight')
        if min_weight:
            loads = loads.filter(weight_kg__gte=min_weight)

        location = request.GET.get('location')
        if location:
            loads = loads.filter(pickup_address__icontains=location)

        loads = loads.order_by('-created_at')[:50]
        serializer = LoadSerializer(loads, many=True)

        return Response({
            'success': True,
            'count': loads.count(),
            'data': serializer.data
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsConsigneeOrCorporate, IsActiveUser])
def search_available_vehicles(request):
    """Search for available vehicles"""
    try:
        vehicles = Vehicle.objects.filter(is_active=True, verification_status='verified')

        vehicle_type = request.GET.get('vehicle_type')
        if vehicle_type:
            vehicles = vehicles.filter(vehicle_type=vehicle_type)

        min_capacity = request.GET.get('min_capacity')
        if min_capacity:
            vehicles = vehicles.filter(capacity_ton__gte=min_capacity)

        location = request.GET.get('location')
        if location:
            schedules = VehicleSchedule.objects.filter(
                vehicle__in=vehicles,
                status='active',
                available_from__lte=timezone.now(),
                available_to__gte=timezone.now()
            ).filter(
                Q(start_location__icontains=location) |
                Q(end_location__icontains=location)
            )
            vehicle_ids = schedules.values_list('vehicle_id', flat=True)
            vehicles = vehicles.filter(vehicle_id__in=vehicle_ids)

        vehicles = vehicles[:50]
        serializer = VehicleSerializer(vehicles, many=True, context={'request': request})

        return Response({
            'success': True,
            'count': vehicles.count(),
            'data': serializer.data
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def estimate_load_price(request):
    """Estimate price for a load without creating it"""
    try:
        serializer = LoadPriceEstimateSerializer(data=request.data)

        if serializer.is_valid():
            return Response({
                'success': True,
                'data': serializer.validated_data['price_details']
            })

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsCorporate, IsActiveUser])
def bulk_create_loads(request):
    """Create multiple loads at once (for corporate users)"""
    try:
        loads_data = request.data.get('loads', [])

        if not loads_data or not isinstance(loads_data, list):
            return Response({
                'success': False,
                'message': 'Please provide a list of loads'
            }, status=status.HTTP_400_BAD_REQUEST)

        if len(loads_data) > 50:
            return Response({
                'success': False,
                'message': 'Cannot create more than 50 loads at once'
            }, status=status.HTTP_400_BAD_REQUEST)

        created_loads = []
        errors = []

        with transaction.atomic():
            for index, load_data in enumerate(loads_data):
                serializer = LoadCreateWithPriceSerializer(
                    data=load_data,
                    context={'request': request}
                )

                if serializer.is_valid():
                    load = serializer.save(consignee=request.user)
                    created_loads.append(LoadSerializer(load).data)
                else:
                    errors.append({
                        'index': index,
                        'errors': serializer.errors
                    })

        response_data = {
            'success': True,
            'message': f'Successfully created {len(created_loads)} loads',
            'data': {
                'created': created_loads,
                'total_created': len(created_loads)
            }
        }

        if errors:
            response_data['errors'] = errors
            response_data['success'] = False
            response_data['message'] = f'Created {len(created_loads)} loads with {len(errors)} errors'

        return Response(response_data, status=status.HTTP_207_MULTI_STATUS if errors else status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ LOAD REQUEST VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def load_requests(request):
    """Get all requests or create new request"""
    try:
        if request.method == 'GET':
            user = request.user

            if user.role in ['consignee', 'corporate']:
                requests = LoadRequest.objects.filter(load__consignee=user).order_by('-created_at')
            elif user.role in ['truck_owner', 'transporter']:
                requests = LoadRequest.objects.filter(requester=user).order_by('-created_at')
            else:
                return Response({'success': False, 'message': 'Your role cannot access load requests'},
                                status=status.HTTP_403_FORBIDDEN)

            serializer = LoadRequestSerializer(requests, many=True, context={'request': request})
            return Response({'success': True, 'count': requests.count(), 'data': serializer.data})

        elif request.method == 'POST':
            if request.user.role not in ['truck_owner', 'transporter']:
                return Response({
                    'success': False,
                    'message': 'Only truck owners and transporters can create load requests'
                }, status=status.HTTP_403_FORBIDDEN)

            serializer = LoadRequestCreateSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                load_request = serializer.save(requester=request.user)

                create_notification(
                    load_request.load.consignee, 'New Load Request',
                    f'{request.user.full_name} has requested to transport your load #{load_request.load.load_id}',
                    'booking'
                )

                return Response({
                    'success': True,
                    'message': 'Load request sent successfully',
                    'data': LoadRequestSerializer(load_request, context={'request': request}).data
                }, status=status.HTTP_201_CREATED)

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def load_request_detail(request, request_id):
    """Get, accept or reject a load request"""
    try:
        load_request = LoadRequest.objects.select_related(
            'load', 'requester', 'vehicle'
        ).get(request_id=request_id)

        if request.method == 'GET':
            if request.user not in [load_request.requester,
                                    load_request.load.consignee] and request.user.role != 'admin':
                return Response({
                    'success': False,
                    'message': 'You do not have permission to view this request'
                }, status=status.HTTP_403_FORBIDDEN)

            serializer = LoadRequestSerializer(load_request, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            if request.user != load_request.load.consignee:
                return Response({
                    'success': False,
                    'message': 'Only the consignee can respond to this request'
                }, status=status.HTTP_403_FORBIDDEN)

            if load_request.status != 'pending':
                return Response({
                    'success': False,
                    'message': f'This request is already {load_request.status}'
                }, status=status.HTTP_400_BAD_REQUEST)

            if load_request.expires_at < timezone.now():
                load_request.status = 'expired'
                load_request.save()
                return Response({'success': False, 'message': 'This request has expired'},
                                status=status.HTTP_400_BAD_REQUEST)

            action = request.data.get('action')

            if action == 'accept':
                return accept_load_request(request, load_request)
            elif action == 'reject':
                return reject_load_request(request, load_request)
            else:
                return Response({
                    'success': False,
                    'message': 'Invalid action. Use "accept" or "reject"'
                }, status=status.HTTP_400_BAD_REQUEST)

    except LoadRequest.DoesNotExist:
        return Response({'success': False, 'message': 'Load request not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def accept_load_request(request, load_request):
    """Accept a load request and create booking"""
    with transaction.atomic():
        load = load_request.load
        load_request.status = 'accepted'
        load_request.responded_at = timezone.now()
        load_request.save()

        load.status = 'assigned'
        load.save()

        # Reject all other pending requests
        LoadRequest.objects.filter(
            load=load, status='pending'
        ).exclude(request_id=load_request.request_id).update(
            status='rejected', responded_at=timezone.now()
        )

        # Financial calculations - keep everything as Decimal
        gst_rate = Decimal('0.18')
        commission_rate = Decimal('0.05')

        # Ensure total_price is Decimal
        total_price = load_request.total_price
        if not isinstance(total_price, Decimal):
            total_price = Decimal(str(total_price))

        tax_amount = (total_price * gst_rate).quantize(Decimal('0.01'))
        total_amount = (total_price + tax_amount).quantize(Decimal('0.01'))
        admin_commission = (total_price * commission_rate).quantize(Decimal('0.01'))
        vendor_payout = (total_price - admin_commission).quantize(Decimal('0.01'))

        # Calculate wallet consumption - convert to float only for calculation, then back to Decimal
        try:
            wallet = Wallet.objects.get(user=load.consignee)
            # Convert to float for the calculator function
            consumption = PricingCalculator.calculate_wallet_consumption(
                float(total_amount), float(wallet.balance)
            )
            wallet_amount_used = Decimal(str(consumption['actual_consumption']))
            cash_amount = Decimal(str(consumption['cash_required']))
        except Wallet.DoesNotExist:
            wallet_amount_used = Decimal('0.00')
            cash_amount = total_amount

        # Create Booking
        booking = Booking.objects.create(
            load=load,
            consignee=load.consignee,
            transporter=load_request.requester,
            vehicle=load_request.vehicle,
            agreed_price=total_price,
            tax_amount=tax_amount,
            total_amount=total_amount,
            pickup_otp=str(random.randint(100000, 999999)),
            delivery_otp=str(random.randint(100000, 999999)),
            delivery_time_commitment=load.pickup_date + timedelta(hours=24)
        )

        # Create Payment
        Payment.objects.create(
            booking=booking,
            payer=load.consignee,
            payee=load_request.requester,
            amount=total_amount,
            payment_gateway='wallet',
            payment_status='escrow_held',
            admin_commission=admin_commission,
            vendor_payout=vendor_payout,
            wallet_amount_used=wallet_amount_used,
            cash_amount_paid=cash_amount
        )

        # Deduct from wallet if used
        if wallet_amount_used > 0 and 'wallet' in locals():
            wallet.balance -= wallet_amount_used
            wallet.save()
            WalletTransaction.objects.create(
                wallet=wallet,
                amount=wallet_amount_used,
                transaction_type='debit',
                reference_type='booking_payment',
                reference_id=booking.booking_id,
                description=f'Payment for booking #{booking.booking_id}'
            )

        # FIXED: Convert ALL numeric values to Decimal properly
        # Get values as Decimal or convert safely
        capacity_ton = load_request.vehicle.capacity_ton
        if isinstance(capacity_ton, Decimal):
            total_capacity_kg = capacity_ton * Decimal('1000')
        else:
            total_capacity_kg = Decimal(str(float(capacity_ton) * 1000))

        weight_kg = load.weight_kg
        if isinstance(weight_kg, Decimal):
            booked_capacity_kg = weight_kg
        else:
            booked_capacity_kg = Decimal(str(float(weight_kg)))

        available_capacity_kg = total_capacity_kg - booked_capacity_kg

        # Ensure scheduled_boarding_time is timezone aware
        scheduled_boarding_time = load.pickup_date
        if timezone.is_naive(scheduled_boarding_time):
            scheduled_boarding_time = timezone.make_aware(scheduled_boarding_time)

        # Create Trip
        trip = Trip.objects.create(
            booking=booking,
            vehicle=load_request.vehicle,
            driver=None,
            owner=load_request.requester,
            from_location=load.pickup_address,
            from_lat=load.pickup_lat,
            from_lng=load.pickup_lng,
            destination=load.drop_address,
            destination_lat=load.drop_lat,
            destination_lng=load.drop_lng,
            total_capacity_kg=total_capacity_kg,
            booked_capacity_kg=booked_capacity_kg,
            available_capacity_kg=available_capacity_kg,
            scheduled_boarding_time=scheduled_boarding_time,
            estimated_delivery_time=scheduled_boarding_time + timedelta(hours=24),
            original_rate=total_price,
            status='scheduled'
        )

        # Update transporter stats - convert to float only for addition
        transporter = load_request.requester
        transporter.total_trips += 1
        # Convert annual_turnover to float for addition, then back to Decimal
        current_turnover = float(transporter.annual_turnover) if transporter.annual_turnover else 0
        transporter.annual_turnover = Decimal(str(current_turnover + float(total_price)))
        transporter.save()

        # Notifications
        create_notification(
            load_request.requester, 'Request Accepted',
            f'Your request for load #{load.load_id} has been accepted. Booking created.',
            'booking'
        )
        create_notification(
            load.consignee, 'Booking Confirmed',
            f'Booking #{booking.booking_id} created successfully with {load_request.requester.full_name}',
            'booking'
        )

        return Response({
            'success': True,
            'message': 'Request accepted and booking created successfully',
            'data': {
                'booking': BookingSerializer(booking).data,
                'trip': TripSerializer(trip).data,
                'request': LoadRequestSerializer(load_request, context={'request': request}).data
            }
        }, status=status.HTTP_201_CREATED)
def reject_load_request(request, load_request):
    """Reject a load request"""
    load_request.status = 'rejected'
    load_request.responded_at = timezone.now()
    load_request.save()

    create_notification(
        load_request.requester, 'Request Rejected',
        f'Your request for load #{load_request.load.load_id} has been rejected.',
        'booking'
    )

    return Response({'success': True, 'message': 'Request rejected successfully'})


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def withdraw_load_request(request, request_id):
    """Withdraw a pending request"""
    try:
        load_request = LoadRequest.objects.get(request_id=request_id)

        if request.user != load_request.requester:
            return Response({
                'success': False,
                'message': 'You can only withdraw your own requests'
            }, status=status.HTTP_403_FORBIDDEN)

        if load_request.status != 'pending':
            return Response({
                'success': False,
                'message': f'Cannot withdraw a {load_request.status} request'
            }, status=status.HTTP_400_BAD_REQUEST)

        load_request.status = 'withdrawn'
        load_request.save()

        return Response({'success': True, 'message': 'Request withdrawn successfully'})

    except LoadRequest.DoesNotExist:
        return Response({'success': False, 'message': 'Load request not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsTruckOwnerOrTransporter, IsActiveUser])
def get_price_estimate(request):
    """Get price estimate for a potential load"""
    try:
        load_id = request.GET.get('load_id')
        vehicle_id = request.GET.get('vehicle_id')

        if not load_id or not vehicle_id:
            return Response({
                'success': False,
                'message': 'Both load_id and vehicle_id are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            load = Load.objects.get(load_id=load_id)
        except Load.DoesNotExist:
            return Response({'success': False, 'message': 'Load not found'},
                            status=status.HTTP_404_NOT_FOUND)

        try:
            vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)
            if vehicle.owner != request.user:
                return Response({'success': False, 'message': 'Vehicle does not belong to you'},
                                status=status.HTTP_403_FORBIDDEN)
        except Vehicle.DoesNotExist:
            return Response({'success': False, 'message': 'Vehicle not found'},
                            status=status.HTTP_404_NOT_FOUND)

        price_details = PricingCalculator.calculate_price(load, vehicle)

        return Response({'success': True, 'data': price_details})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ TRIP VIEWS ============
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsTruckOwnerOrTransporter, IsActiveUser])
def create_trip(request):
    """Create a new trip (at boarding point or day before)"""
    try:
        vehicle_id = request.data.get('vehicle_id')

        try:
            vehicle = Vehicle.objects.get(vehicle_id=vehicle_id, owner=request.user)
        except Vehicle.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Vehicle not found or does not belong to you'
            }, status=status.HTTP_400_BAD_REQUEST)

        total_capacity_kg = float(vehicle.capacity_ton) * 1000

        trip_data = {
            'vehicle': vehicle,
            'owner': request.user,
            'from_location': request.data.get('from_location'),
            'from_lat': request.data.get('from_lat'),
            'from_lng': request.data.get('from_lng'),
            'destination': request.data.get('destination'),
            'destination_lat': request.data.get('destination_lat'),
            'destination_lng': request.data.get('destination_lng'),
            'trip_type': request.data.get('trip_type', 'one_way'),
            'total_capacity_kg': total_capacity_kg,
            'available_capacity_kg': total_capacity_kg,
            'scheduled_boarding_time': request.data.get('scheduled_boarding_time'),
            'estimated_delivery_time': request.data.get('estimated_delivery_time'),
            'original_rate': request.data.get('original_rate', 0),
            'is_return_trip_available': request.data.get('is_return_trip_available', False),
            'status': 'scheduled'
        }

        if request.data.get('is_return_trip_available'):
            trip_data.update({
                'return_from_location': request.data.get('return_from_location'),
                'return_from_lat': request.data.get('return_from_lat'),
                'return_from_lng': request.data.get('return_from_lng'),
                'return_destination': request.data.get('return_destination'),
                'return_available_from': request.data.get('return_available_from'),
                'return_available_to': request.data.get('return_available_to'),
            })

        trip = Trip.objects.create(**trip_data)

        return Response({
            'success': True,
            'message': 'Trip created successfully',
            'data': TripSerializer(trip).data
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_trips(request):
    """Get trips based on user role"""
    try:
        user = request.user
        status_filter = request.GET.get('status')

        if user.role in ['truck_owner', 'transporter']:
            trips = Trip.objects.filter(owner=user)
        elif user.role == 'driver':
            trips = Trip.objects.filter(driver=user)
        else:
            trips = Trip.objects.none()

        if status_filter:
            trips = trips.filter(status=status_filter)

        trips = trips.order_by('-created_at')
        serializer = TripSerializer(trips, many=True)

        return Response({
            'success': True,
            'count': trips.count(),
            'data': serializer.data
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'PATCH'])
@permission_classes([IsAuthenticated, IsActiveUser])
def trip_detail(request, trip_id):
    """Get or update trip details"""
    try:
        trip = Trip.objects.get(trip_id=trip_id)

        if request.user not in [trip.owner, trip.driver] and request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'You do not have permission to access this trip'
            }, status=status.HTTP_403_FORBIDDEN)

        if request.method == 'GET':
            serializer = TripSerializer(trip)
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            if request.user not in [trip.owner, trip.driver]:
                return Response({
                    'success': False,
                    'message': 'Only trip owner or driver can update'
                }, status=status.HTTP_403_FORBIDDEN)

            if 'current_location' in request.data:
                trip.current_location = request.data.get('current_location')
                trip.current_lat = request.data.get('current_lat')
                trip.current_lng = request.data.get('current_lng')
                trip.last_location_update = timezone.now()

                location_history = trip.location_history or []
                location_history.append({
                    'lat': float(trip.current_lat),
                    'lng': float(trip.current_lng),
                    'address': trip.current_location,
                    'timestamp': trip.last_location_update.isoformat()
                })
                trip.location_history = location_history[-100:]

            if 'status' in request.data:
                new_status = request.data.get('status')
                old_status = trip.status
                trip.status = new_status

                if new_status == 'boarding' and old_status == 'scheduled':
                    trip.actual_boarding_time = timezone.now()
                elif new_status == 'delivered':
                    trip.actual_delivery_time = timezone.now()

                    if trip.driver:
                        trip.driver.total_trips += 1
                        trip.driver.successful_deliveries += 1
                        trip.driver.save()

            if 'is_halted' in request.data:
                trip.is_halted = request.data.get('is_halted')
                if trip.is_halted:
                    trip.halt_start_time = timezone.now()
                    trip.halt_location = request.data.get('halt_location')
                    trip.halt_reason = request.data.get('halt_reason')
                else:
                    trip.halt_end_time = timezone.now()

            trip.save()

            return Response({
                'success': True,
                'message': 'Trip updated successfully',
                'data': TripSerializer(trip).data
            })

    except Trip.DoesNotExist:
        return Response({'success': False, 'message': 'Trip not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def trip_update_location(request, trip_id):
    """Update trip location"""
    try:
        trip = Trip.objects.get(trip_id=trip_id)

        if request.user not in [trip.owner, trip.driver]:
            return Response({
                'success': False,
                'message': 'Only trip owner or driver can update location'
            }, status=status.HTTP_403_FORBIDDEN)

        latitude = request.data.get('latitude')
        longitude = request.data.get('longitude')
        location_text = request.data.get('location_text', '')

        if not latitude or not longitude:
            return Response({
                'success': False,
                'message': 'Latitude and longitude are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        trip.current_lat = latitude
        trip.current_lng = longitude
        trip.current_location = location_text
        trip.last_location_update = timezone.now()
        trip.save()

        location = TripLocation.objects.create(
            trip=trip,
            latitude=latitude,
            longitude=longitude,
            location_address=location_text
        )

        if trip.estimated_delivery_time and timezone.now() > trip.estimated_delivery_time:
            delay = PricingCalculator.calculate_delay_penalty(
                trip.estimated_delivery_time,
                timezone.now(),
                float(trip.original_rate)
            )

            if delay['delay_minutes'] > 30:
                trip.status = 'delayed'
                trip.delay_minutes = delay['delay_minutes']
                trip.delay_reason = 'Estimated delivery time exceeded'
                trip.save()

                if delay['delay_minutes'] > 120:
                    Penalty.objects.create(
                        booking=trip.booking,
                        trip=trip,
                        penalty_type='late_delivery',
                        description=f'Delivery delayed by {delay["delay_minutes"]} minutes',
                        penalty_amount=Decimal(str(delay['penalty_amount'])),
                        delay_minutes=delay['delay_minutes'],
                        rating_impact=-2,
                        visibility_reduction_days=7,
                        status='pending',
                        applied_to=trip.driver or trip.owner,
                        applied_by=request.user if request.user.role == 'admin' else None
                    )

        return Response({
            'success': True,
            'message': 'Location updated',
            'data': TripLocationSerializer(location).data
        }, status=status.HTTP_201_CREATED)

    except Trip.DoesNotExist:
        return Response({'success': False, 'message': 'Trip not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsDriver, IsActiveUser])
def driver_start_trip(request, trip_id):
    """Driver starts the trip (at boarding point)"""
    try:
        trip = Trip.objects.get(trip_id=trip_id, driver=request.user)

        if trip.status != 'scheduled':
            return Response({
                'success': False,
                'message': f'Cannot start trip from {trip.status} status'
            }, status=status.HTTP_400_BAD_REQUEST)

        trip.status = 'boarding'
        trip.actual_boarding_time = timezone.now()
        trip.save()

        if trip.booking:
            trip.booking.booking_status = 'at_pickup'
            trip.booking.save()

        create_notification(
            trip.booking.consignee,
            'Driver Arrived',
            f'Driver has arrived at pickup location for booking #{trip.booking.booking_id}',
            'booking'
        )

        return Response({
            'success': True,
            'message': 'Trip started successfully',
            'data': TripSerializer(trip).data
        })

    except Trip.DoesNotExist:
        return Response({'success': False, 'message': 'Trip not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsDriver, IsActiveUser])
def driver_mark_halted(request, trip_id):
    """Driver marks trip as halted"""
    try:
        trip = Trip.objects.get(trip_id=trip_id, driver=request.user)

        if trip.status != 'in_transit':
            return Response({
                'success': False,
                'message': 'Can only halt trips that are in transit'
            }, status=status.HTTP_400_BAD_REQUEST)

        trip.is_halted = True
        trip.halt_start_time = timezone.now()
        trip.halt_location = request.data.get('halt_location', trip.current_location)
        trip.halt_reason = request.data.get('halt_reason', '')
        trip.save()

        return Response({
            'success': True,
            'message': 'Trip marked as halted',
            'data': TripSerializer(trip).data
        })

    except Trip.DoesNotExist:
        return Response({'success': False, 'message': 'Trip not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsDriver, IsActiveUser])
def driver_resume_from_halt(request, trip_id):
    """Driver resumes trip from halt"""
    try:
        trip = Trip.objects.get(trip_id=trip_id, driver=request.user)

        if not trip.is_halted:
            return Response({
                'success': False,
                'message': 'Trip is not halted'
            }, status=status.HTTP_400_BAD_REQUEST)

        trip.is_halted = False
        trip.halt_end_time = timezone.now()
        trip.save()

        if trip.halt_start_time and trip.halt_end_time:
            halt_hours = (trip.halt_end_time - trip.halt_start_time).total_seconds() / 3600
            if halt_hours > 2:
                haulting_charge = PricingCalculator.calculate_haulting_charge(halt_hours)

                if haulting_charge > 0 and trip.booking:
                    ExtraCharge.objects.create(
                        booking=trip.booking,
                        charge_type='haulting',
                        description=f'Haulting charge for {round(halt_hours, 2)} hours',
                        amount=Decimal(str(haulting_charge)),
                        created_by=request.user
                    )

        return Response({
            'success': True,
            'message': 'Trip resumed successfully',
            'data': TripSerializer(trip).data
        })

    except Trip.DoesNotExist:
        return Response({'success': False, 'message': 'Trip not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def search_return_trips(request):
    """Search for available return trips"""
    try:
        from_lat = request.GET.get('from_lat')
        from_lng = request.GET.get('from_lng')
        to_location = request.GET.get('to_location')
        required_capacity = request.GET.get('required_capacity', 0)

        trips = Trip.objects.filter(
            is_return_trip_available=True,
            status__in=['in_transit', 'boarding'],
            available_capacity_kg__gte=required_capacity
        )

        if from_lat and from_lng:
            from_lat = float(from_lat)
            from_lng = float(from_lng)

            trips = trips.filter(
                return_from_lat__gte=from_lat - 0.5,
                return_from_lat__lte=from_lat + 0.5,
                return_from_lng__gte=from_lng - 0.5,
                return_from_lng__lte=from_lng + 0.5
            )

        if to_location:
            trips = trips.filter(return_destination__icontains=to_location)

        trips = trips.order_by('-created_at')[:50]

        offers = []
        for trip in trips:
            offer = {
                'trip_id': trip.trip_id,
                'from_location': trip.return_from_location,
                'from_lat': float(trip.return_from_lat),
                'from_lng': float(trip.return_from_lng),
                'to_location': trip.return_destination,
                'to_lat': float(trip.destination_lat),
                'to_lng': float(trip.destination_lng),
                'available_space_kg': float(trip.available_capacity_kg),
                'available_from': trip.return_available_from,
                'available_to': trip.return_available_to,
                'vehicle_details': {
                    'registration_number': trip.vehicle.registration_number,
                    'vehicle_type': trip.vehicle.get_vehicle_type_display(),
                    'capacity_ton': float(trip.vehicle.capacity_ton)
                }
            }
            offers.append(offer)

        return Response({
            'success': True,
            'count': len(offers),
            'data': offers
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ BOOKING VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_bookings(request):
    """Get all bookings for the current user"""
    try:
        user = request.user
        status_filter = request.GET.get('status')

        if user.role in ['consignee', 'corporate']:
            bookings = Booking.objects.filter(consignee=user)
        elif user.role in ['transporter', 'truck_owner']:
            bookings = Booking.objects.filter(transporter=user)
        elif user.role == 'driver':
            bookings = Booking.objects.filter(driver=user)
        else:
            bookings = Booking.objects.none()

        if status_filter:
            bookings = bookings.filter(booking_status=status_filter)

        bookings = bookings.select_related('load', 'vehicle', 'driver').prefetch_related(
            'extra_charges', 'penalties', 'trip'
        ).order_by('-created_at')

        serializer = BookingSerializer(bookings, many=True)

        return Response({
            'success': True,
            'count': bookings.count(),
            'data': serializer.data
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated, IsActiveUser, IsBookingParticipant])
def booking_detail(request, booking_id):
    """Get or update booking details"""
    try:
        booking = Booking.objects.select_related(
            'load', 'consignee', 'transporter', 'vehicle', 'driver'
        ).prefetch_related('extra_charges', 'penalties', 'trip').get(booking_id=booking_id)

        if request.method == 'GET':
            serializer = BookingSerializer(booking)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'PUT':
            if request.user.role not in ['transporter', 'admin'] and request.user != booking.transporter:
                return Response({
                    'success': False,
                    'message': 'Only transporter can update booking details'
                }, status=status.HTTP_403_FORBIDDEN)

            serializer = BookingUpdateSerializer(booking, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Booking updated successfully',
                    'data': BookingSerializer(booking).data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Booking.DoesNotExist:
        return Response({'success': False, 'message': 'Booking not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser, IsBookingParticipant])
def add_extra_charge(request, booking_id):
    """Add extra charges to booking (Hamali, Loading, etc.)"""
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        if request.user not in [booking.consignee, booking.transporter] and request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'You do not have permission to add charges'
            }, status=status.HTTP_403_FORBIDDEN)

        data = request.data.copy()
        data['booking'] = booking_id

        serializer = ExtraChargeSerializer(data=data)
        if serializer.is_valid():
            charge = serializer.save(created_by=request.user)

            total_extra = ExtraCharge.objects.filter(booking=booking).aggregate(
                total=Sum('amount')
            )['total'] or 0

            booking.total_amount = booking.agreed_price + booking.tax_amount + total_extra
            booking.save()

            return Response({
                'success': True,
                'message': f'{charge.get_charge_type_display()} added successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Booking.DoesNotExist:
        return Response({'success': False, 'message': 'Booking not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated, IsActiveUser])
def remove_extra_charge(request, charge_id):
    """Remove extra charge"""
    try:
        charge = ExtraCharge.objects.get(charge_id=charge_id)
        booking = charge.booking

        if request.user not in [charge.created_by, booking.consignee,
                                booking.transporter] and request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'You do not have permission to delete this charge'
            }, status=status.HTTP_403_FORBIDDEN)

        charge.delete()

        total_extra = ExtraCharge.objects.filter(booking=booking).aggregate(
            total=Sum('amount')
        )['total'] or 0
        booking.total_amount = booking.agreed_price + booking.tax_amount + total_extra
        booking.save()

        return Response({
            'success': True,
            'message': 'Charge removed successfully'
        })

    except ExtraCharge.DoesNotExist:
        return Response({'success': False, 'message': 'Charge not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser, IsBookingParticipant])
def verify_booking_otp(request, booking_id):
    """Verify pickup or delivery OTP (Amazon-style)"""
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        otp_type = request.data.get('type')
        otp = request.data.get('otp')

        if not otp_type or not otp:
            return Response({
                'success': False,
                'message': 'OTP type and value are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        if otp_type == 'pickup':
            if booking.pickup_otp != otp:
                return Response({'success': False, 'message': 'Invalid pickup OTP'},
                                status=status.HTTP_400_BAD_REQUEST)
            booking.booking_status = 'loaded'
            booking.save()

            if hasattr(booking, 'trip'):
                booking.trip.status = 'in_transit'
                booking.trip.save()

        elif otp_type == 'delivery':
            if booking.delivery_otp != otp:
                return Response({'success': False, 'message': 'Invalid delivery OTP'},
                                status=status.HTTP_400_BAD_REQUEST)
            booking.booking_status = 'completed'
            booking.completed_at = timezone.now()
            booking.actual_delivery_time = timezone.now()
            booking.save()

            if hasattr(booking, 'trip'):
                booking.trip.status = 'delivered'
                booking.trip.actual_delivery_time = timezone.now()
                booking.trip.save()

            payment = Payment.objects.filter(booking=booking).first()
            if payment:
                payment.payment_status = 'released_to_vendor'
                payment.released_at = timezone.now()
                payment.save()

                try:
                    wallet = Wallet.objects.get(user=payment.payee)
                    wallet.balance += payment.vendor_payout
                    wallet.save()

                    WalletTransaction.objects.create(
                        wallet=wallet,
                        amount=payment.vendor_payout,
                        transaction_type='credit',
                        reference_type='booking_payment',
                        reference_id=booking.booking_id,
                        description=f'Payment for booking #{booking.booking_id}'
                    )

                    reward_amount = payment.vendor_payout * Decimal('0.01')
                    wallet.reward_points += reward_amount
                    wallet.save()

                    create_notification(
                        payment.payee,
                        'Payment Released',
                        f'Payment of ₹{payment.vendor_payout} has been released. You earned ₹{reward_amount} reward points!',
                        'payment'
                    )
                except Wallet.DoesNotExist:
                    pass

        else:
            return Response({
                'success': False,
                'message': 'Invalid OTP type. Use "pickup" or "delivery"'
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'success': True,
            'message': f'{otp_type.capitalize()} OTP verified successfully',
            'data': {'booking_status': booking.booking_status}
        })

    except Booking.DoesNotExist:
        return Response({'success': False, 'message': 'Booking not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ TRACKING VIEWS ============
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def update_tracking(request):
    try:
        booking_id = request.data.get('booking')
        try:
            booking = Booking.objects.get(booking_id=booking_id)
        except Booking.DoesNotExist:
            return Response({
                'success': False,
                'message': 'Booking not found'
            }, status=status.HTTP_404_NOT_FOUND)

        if request.user not in [booking.transporter, booking.driver] and request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'Only transporter or driver can update tracking'
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = TrackingCreateSerializer(data=request.data)
        if serializer.is_valid():
            tracking = serializer.save()
            return Response({
                'success': True,
                'message': 'Location updated',
                'data': TrackingSerializer(tracking).data
            }, status=status.HTTP_201_CREATED)
        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def get_tracking(request, booking_id):
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        if request.user not in [booking.consignee, booking.transporter,
                                booking.driver] and request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'You do not have permission to view tracking for this booking'
            }, status=status.HTTP_403_FORBIDDEN)

        tracking = ShipmentTracking.objects.filter(booking=booking).order_by('-timestamp')[:100]
        serializer = TrackingSerializer(tracking, many=True)

        return Response({
            'success': True,
            'data': {
                'booking_id': booking_id,
                'current_status': booking.booking_status,
                'tracking': serializer.data
            }
        })

    except Booking.DoesNotExist:
        return Response({'success': False, 'message': 'Booking not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ WALLET VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_wallet(request):
    """Get wallet details"""
    try:
        wallet, created = Wallet.objects.get_or_create(user=request.user)
        serializer = WalletSerializer(wallet)
        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser, HasWallet])
def wallet_transactions(request):
    """Get wallet transactions"""
    try:
        wallet = Wallet.objects.get(user=request.user)
        transactions = WalletTransaction.objects.filter(wallet=wallet).order_by('-created_at')
        serializer = WalletTransactionSerializer(transactions, many=True)
        return Response({'success': True, 'data': serializer.data})

    except Wallet.DoesNotExist:
        return Response({'success': False, 'message': 'Wallet not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def add_wallet_money(request):
    """Add money to wallet (deposit)"""
    try:
        amount = request.data.get('amount')
        if not amount or float(amount) <= 0:
            return Response({
                'success': False,
                'message': 'Valid amount is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        wallet, created = Wallet.objects.get_or_create(user=request.user)

        wallet.balance += Decimal(str(amount))
        wallet.save()

        WalletTransaction.objects.create(
            wallet=wallet,
            amount=amount,
            transaction_type='credit',
            reference_type='deposit',
            description='Wallet top-up'
        )

        return Response({
            'success': True,
            'message': 'Money added to wallet successfully',
            'data': {'new_balance': wallet.balance}
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def calculate_wallet_consumption(request):
    """Calculate how much can be paid from wallet (10% per trip)"""
    try:
        serializer = WalletConsumptionSerializer(data=request.data)
        if serializer.is_valid():
            return Response({
                'success': True,
                'data': serializer.validated_data['consumption']
            })
        return Response({'success': False, 'errors': serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ RATING VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_ratings(request):
    """Get user's ratings or create new rating"""
    try:
        if request.method == 'GET':
            given = Rating.objects.filter(reviewer=request.user)
            received = Rating.objects.filter(reviewee=request.user)

            return Response({
                'success': True,
                'data': {
                    'given': RatingSerializer(given, many=True).data,
                    'received': RatingSerializer(received, many=True).data,
                    'average_rating': received.aggregate(avg=Avg('score'))['avg'] or 0
                }
            })

        elif request.method == 'POST':
            serializer = RatingCreateSerializer(data=request.data)
            if serializer.is_valid():
                rating = serializer.save(reviewer=request.user)

                reviewee = rating.reviewee
                avg_rating = Rating.objects.filter(reviewee=reviewee).aggregate(avg=Avg('score'))['avg']
                reviewee.rating = round(avg_rating, 2) if avg_rating else 0
                reviewee.save()

                return Response({
                    'success': True,
                    'message': 'Rating submitted successfully',
                    'data': RatingSerializer(rating).data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ PENALTY VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_penalties(request):
    """Get penalties for current user"""
    try:
        penalties = Penalty.objects.filter(applied_to=request.user).order_by('-created_at')
        serializer = PenaltySerializer(penalties, many=True)

        return Response({
            'success': True,
            'data': serializer.data
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ FESTIVAL GIFT VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def eligible_festival_gifts(request):
    """Check eligible festival gifts for current user"""
    try:
        now = timezone.now()
        gifts = FestivalGift.objects.filter(
            recipient=request.user,
            is_delivered=False
        ).order_by('-created_at')

        eligible = []
        for gift in gifts:
            if (request.user.rating >= gift.minimum_rating and
                    request.user.annual_turnover >= gift.minimum_turnover):
                eligible.append(gift)

        serializer = FestivalGiftSerializer(eligible, many=True)

        return Response({
            'success': True,
            'data': serializer.data
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ NOTIFICATION VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_notifications(request):
    try:
        unread_only = request.GET.get('unread_only', 'false').lower() == 'true'

        notifications = Notification.objects.filter(user=request.user)
        if unread_only:
            notifications = notifications.filter(is_read=False)

        notifications = notifications.order_by('-created_at')
        serializer = NotificationSerializer(notifications, many=True)

        return Response({
            'success': True,
            'unread_count': notifications.filter(is_read=False).count(),
            'data': serializer.data
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser, IsNotificationOwner])
def mark_notification_read(request, notification_id):
    try:
        notification = Notification.objects.get(notification_id=notification_id)
        notification.is_read = True
        notification.save()
        return Response({'success': True, 'message': 'Notification marked as read'})

    except Notification.DoesNotExist:
        return Response({'success': False, 'message': 'Notification not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ DRIVER SPECIFIC VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsDriver, IsActiveUser])
def driver_dashboard(request):
    """Driver's personalized dashboard"""
    try:
        active_bookings = Booking.objects.filter(
            driver=request.user,
            booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']
        ).select_related('load', 'vehicle', 'transporter').order_by('-created_at')

        current_trip = Trip.objects.filter(
            driver=request.user,
            status__in=['boarding', 'in_transit']
        ).first()

        completed_trips = Booking.objects.filter(
            driver=request.user,
            booking_status='completed'
        ).count()

        total_earnings = Booking.objects.filter(
            driver=request.user,
            booking_status='completed'
        ).aggregate(total=Sum('agreed_price'))['total'] or 0

        penalties = Penalty.objects.filter(
            applied_to=request.user,
            status='applied'
        ).aggregate(total=Sum('penalty_amount'))['total'] or 0

        return Response({
            'success': True,
            'data': {
                'active_bookings_count': active_bookings.count(),
                'current_trip': TripSerializer(current_trip).data if current_trip else None,
                'completed_trips': completed_trips,
                'total_earnings': total_earnings,
                'penalties': penalties,
                'net_earnings': total_earnings - penalties,
                'rating': float(request.user.rating),
                'visibility_score': float(request.user.visibility_score),
                'upcoming_bookings': BookingSerializer(active_bookings[:5], many=True).data,
            }
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsDriver, IsActiveUser])
def driver_accept_booking(request, booking_id):
    """Driver accepts a booking assignment"""
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        if booking.booking_status != 'confirmed':
            return Response({
                'success': False,
                'message': 'This booking is not available for acceptance'
            }, status=status.HTTP_400_BAD_REQUEST)

        if booking.driver:
            return Response({
                'success': False,
                'message': 'Driver already assigned to this booking'
            }, status=status.HTTP_400_BAD_REQUEST)

        booking.driver = request.user
        booking.booking_status = 'driver_assigned'
        booking.save()

        if hasattr(booking, 'trip'):
            booking.trip.driver = request.user
            booking.trip.save()

        create_notification(
            booking.transporter,
            'Driver Assigned',
            f'Driver {request.user.full_name} has accepted booking #{booking_id}',
            'booking'
        )

        return Response({
            'success': True,
            'message': 'Booking accepted successfully',
            'data': BookingSerializer(booking).data
        })

    except Booking.DoesNotExist:
        return Response({'success': False, 'message': 'Booking not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN VEHICLE CATEGORIES & PRICING ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_vehicle_categories(request):
    """Manage vehicle categories"""
    try:
        if request.method == 'GET':
            categories = VehicleCategory.objects.all()
            serializer = VehicleCategorySerializer(categories, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = VehicleCategorySerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()

                AdminLog.objects.create(
                    admin_user=request.user,
                    action_type='CATEGORY_CREATE',
                    target_id=serializer.data.get('category_id'),
                    details=f'Created vehicle category: {serializer.data.get("name")}'
                )

                return Response({
                    'success': True,
                    'message': 'Vehicle category created successfully',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_vehicle_category_detail(request, category_id):
    """Get, update or delete vehicle category"""
    try:
        category = VehicleCategory.objects.get(category_id=category_id)

        if request.method == 'GET':
            serializer = VehicleCategorySerializer(category)
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = VehicleCategorySerializer(category, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()

                AdminLog.objects.create(
                    admin_user=request.user,
                    action_type='CATEGORY_UPDATE',
                    target_id=category_id,
                    details=f'Updated vehicle category: {category.name}'
                )

                return Response({
                    'success': True,
                    'message': 'Vehicle category updated successfully',
                    'data': serializer.data
                })

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            name = category.name
            category.delete()

            AdminLog.objects.create(
                admin_user=request.user,
                action_type='CATEGORY_DELETE',
                target_id=category_id,
                details=f'Deleted vehicle category: {name}'
            )

            return Response({'success': True, 'message': 'Vehicle category deleted successfully'})

    except VehicleCategory.DoesNotExist:
        return Response({'success': False, 'message': 'Vehicle category not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_pricing_slabs(request):
    """Manage pricing slabs"""
    try:
        if request.method == 'GET':
            category_id = request.GET.get('category_id')
            slabs = PricingSlab.objects.all()
            if category_id:
                slabs = slabs.filter(vehicle_category_id=category_id)
            serializer = PricingSlabSerializer(slabs, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = PricingSlabSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()

                AdminLog.objects.create(
                    admin_user=request.user,
                    action_type='PRICING_SLAB_CREATE',
                    target_id=serializer.data.get('slab_id'),
                    details='Created pricing slab'
                )

                return Response({
                    'success': True,
                    'message': 'Pricing slab created successfully',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_pricing_slab_detail(request, slab_id):
    """Get, update or delete pricing slab"""
    try:
        slab = PricingSlab.objects.get(slab_id=slab_id)

        if request.method == 'GET':
            serializer = PricingSlabSerializer(slab)
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = PricingSlabSerializer(slab, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()

                AdminLog.objects.create(
                    admin_user=request.user,
                    action_type='PRICING_SLAB_UPDATE',
                    target_id=slab_id,
                    details='Updated pricing slab'
                )

                return Response({
                    'success': True,
                    'message': 'Pricing slab updated successfully',
                    'data': serializer.data
                })

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            slab.delete()

            AdminLog.objects.create(
                admin_user=request.user,
                action_type='PRICING_SLAB_DELETE',
                target_id=slab_id,
                details='Deleted pricing slab'
            )

            return Response({'success': True, 'message': 'Pricing slab deleted successfully'})

    except PricingSlab.DoesNotExist:
        return Response({'success': False, 'message': 'Pricing slab not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN PENALTY MANAGEMENT ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_penalties(request):
    """Manage penalties"""
    try:
        if request.method == 'GET':
            status_filter = request.GET.get('status')
            penalties = Penalty.objects.all()
            if status_filter:
                penalties = penalties.filter(status=status_filter)
            penalties = penalties.order_by('-created_at')
            serializer = PenaltySerializer(penalties, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = PenaltySerializer(data=request.data)
            if serializer.is_valid():
                penalty = serializer.save()

                if penalty.visibility_reduction_days > 0:
                    user = penalty.applied_to
                    user.visibility_score = max(0, float(user.visibility_score) - 20)
                    user.save()

                return Response({
                    'success': True,
                    'message': 'Penalty applied successfully',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_update_penalty(request, penalty_id):
    """Update penalty status"""
    try:
        penalty = Penalty.objects.get(penalty_id=penalty_id)

        new_status = request.data.get('status')
        if new_status:
            penalty.status = new_status
            penalty.resolved_at = timezone.now() if new_status in ['resolved', 'closed'] else None
            penalty.save()

            if new_status == 'applied' and penalty.visibility_reduction_days > 0:
                user = penalty.applied_to
                user.visibility_score = max(0, float(user.visibility_score) - 20)
                user.save()

        return Response({
            'success': True,
            'message': 'Penalty updated successfully',
            'data': PenaltySerializer(penalty).data
        })

    except Penalty.DoesNotExist:
        return Response({'success': False, 'message': 'Penalty not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN FESTIVAL GIFT MANAGEMENT ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_festival_gifts(request):
    """Manage festival gifts"""
    try:
        if request.method == 'GET':
            festival = request.GET.get('festival')
            gifts = FestivalGift.objects.all()
            if festival:
                gifts = gifts.filter(festival=festival)
            gifts = gifts.order_by('-created_at')
            serializer = FestivalGiftSerializer(gifts, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = FestivalGiftSerializer(data=request.data)
            if serializer.is_valid():
                gift = serializer.save(created_by=request.user)

                eligible_users = User.objects.filter(
                    role__in=['driver', 'truck_owner', 'transporter'],
                    rating__gte=gift.minimum_rating,
                    annual_turnover__gte=gift.minimum_turnover,
                    is_active=True
                )

                for user in eligible_users:
                    create_notification(
                        user,
                        f'Festival Gift: {gift.get_festival_display()}',
                        f'You are eligible for a {gift.get_gift_type_display()} worth ₹{gift.gift_value}!',
                        'festival_gift'
                    )

                return Response({
                    'success': True,
                    'message': f'Gift created and {eligible_users.count()} users notified',
                    'data': serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_mark_gift_delivered(request, gift_id):
    """Mark gift as delivered"""
    try:
        gift = FestivalGift.objects.get(gift_id=gift_id)

        gift.is_delivered = True
        gift.delivered_at = timezone.now()
        gift.save()

        create_notification(
            gift.recipient,
            'Gift Delivered',
            f'Your {gift.get_festival_display()} gift has been delivered!',
            'festival_gift'
        )

        return Response({
            'success': True,
            'message': 'Gift marked as delivered'
        })

    except FestivalGift.DoesNotExist:
        return Response({'success': False, 'message': 'Gift not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN TRIP MONITORING ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_monitor_trips(request):
    """Admin dashboard for trip monitoring"""
    try:
        active_trips = Trip.objects.filter(
            status__in=['boarding', 'in_transit', 'halted']
        ).select_related('vehicle', 'driver', 'booking')

        delayed_trips = Trip.objects.filter(
            status='delayed'
        ).select_related('vehicle', 'driver', 'booking')

        long_haulting = Trip.objects.filter(
            is_halted=True,
            halt_start_time__lte=timezone.now() - timedelta(hours=24)
        )

        stats = {
            'total_active': active_trips.count(),
            'total_delayed': delayed_trips.count(),
            'long_haulting': long_haulting.count(),
            'average_delay_minutes': delayed_trips.aggregate(avg=Avg('delay_minutes'))['avg'] or 0,
            'trips_by_status': active_trips.values('status').annotate(count=Count('status')),
            'recent_penalties': Penalty.objects.filter(
                created_at__gte=timezone.now() - timedelta(days=7)
            ).count()
        }

        return Response({
            'success': True,
            'data': {
                'statistics': stats,
                'active_trips': TripSerializer(active_trips[:20], many=True).data,
                'delayed_trips': TripSerializer(delayed_trips[:10], many=True).data,
                'long_haulting_trips': TripSerializer(long_haulting[:10], many=True).data
            }
        })

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN REPORTS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_reports(request):
    """Generate various reports"""
    try:
        report_type = request.GET.get('type', 'summary')
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date:
            start_date = timezone.datetime.fromisoformat(start_date)
        else:
            start_date = timezone.now() - timedelta(days=30)

        if end_date:
            end_date = timezone.datetime.fromisoformat(end_date)
        else:
            end_date = timezone.now()

        if report_type == 'trip_performance':
            trips = Trip.objects.filter(
                created_at__range=[start_date, end_date]
            ).select_related('vehicle', 'driver')

            total_trips = trips.count()
            on_time_deliveries = trips.filter(
                status='delivered',
                actual_delivery_time__lte=models.F('estimated_delivery_time')
            ).count()
            delayed_trips = trips.filter(status='delayed').count()

            driver_performance = trips.values(
                'driver__full_name'
            ).annotate(
                total=Count('trip_id'),
                delayed=Count('trip_id', filter=Q(status='delayed')),
                on_time=Count('trip_id', filter=Q(
                    status='delivered',
                    actual_delivery_time__lte=models.F('estimated_delivery_time')
                ))
            )[:10]

            return Response({
                'success': True,
                'data': {
                    'period': {'start': start_date, 'end': end_date},
                    'total_trips': total_trips,
                    'on_time_deliveries': on_time_deliveries,
                    'on_time_percentage': round((on_time_deliveries / total_trips * 100) if total_trips > 0 else 0, 2),
                    'delayed_trips': delayed_trips,
                    'delay_percentage': round((delayed_trips / total_trips * 100) if total_trips > 0 else 0, 2),
                    'driver_performance': list(driver_performance)
                }
            })

        elif report_type == 'revenue':
            payments = Payment.objects.filter(
                created_at__range=[start_date, end_date],
                payment_status='released_to_vendor'
            )

            total_revenue = payments.aggregate(Sum('admin_commission'))['admin_commission__sum'] or 0
            total_payouts = payments.aggregate(Sum('vendor_payout'))['vendor_payout__sum'] or 0
            total_wallet_usage = payments.aggregate(Sum('wallet_amount_used'))['wallet_amount_used__sum'] or 0

            revenue_by_vehicle = Booking.objects.filter(
                created_at__range=[start_date, end_date]
            ).values('vehicle__vehicle_type').annotate(
                total=Sum('total_amount'),
                count=Count('booking_id')
            )

            return Response({
                'success': True,
                'data': {
                    'period': {'start': start_date, 'end': end_date},
                    'total_revenue': total_revenue,
                    'total_payouts': total_payouts,
                    'total_transactions': payments.count(),
                    'wallet_usage': total_wallet_usage,
                    'revenue_by_vehicle': list(revenue_by_vehicle)
                }
            })

        elif report_type == 'penalties':
            penalties = Penalty.objects.filter(
                created_at__range=[start_date, end_date],
                status='applied'
            )

            total_penalties = penalties.count()
            total_amount = penalties.aggregate(Sum('penalty_amount'))['penalty_amount__sum'] or 0

            by_type = penalties.values('penalty_type').annotate(
                count=Count('penalty_id'),
                total=Sum('penalty_amount')
            )

            top_offenders = penalties.values(
                'applied_to__full_name'
            ).annotate(
                count=Count('penalty_id'),
                total=Sum('penalty_amount')
            ).order_by('-total')[:10]

            return Response({
                'success': True,
                'data': {
                    'period': {'start': start_date, 'end': end_date},
                    'total_penalties': total_penalties,
                    'total_amount': total_amount,
                    'by_type': list(by_type),
                    'top_offenders': list(top_offenders)
                }
            })

        elif report_type == 'users':
            users = User.objects.filter(created_at__range=[start_date, end_date])

            total_users = users.count()
            users_by_role = users.values('role').annotate(count=Count('user_id'))
            verified_users = users.filter(is_verified=True).count()

            top_rated = User.objects.filter(
                role__in=['driver', 'truck_owner', 'transporter'],
                rating__gt=0
            ).order_by('-rating')[:10]

            return Response({
                'success': True,
                'data': {
                    'period': {'start': start_date, 'end': end_date},
                    'total_users': total_users,
                    'verified_users': verified_users,
                    'verification_rate': round((verified_users / total_users * 100) if total_users > 0 else 0, 2),
                    'users_by_role': list(users_by_role),
                    'top_rated': [
                        {'name': u.full_name, 'role': u.role, 'rating': float(u.rating)}
                        for u in top_rated
                    ]
                }
            })

        else:
            return Response({
                'success': False,
                'message': 'Invalid report type'
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN USER MANAGEMENT ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_users_list(request):
    try:
        role = request.GET.get('role')
        status_filter = request.GET.get('status')
        search = request.GET.get('search')

        users = User.objects.all()
        if role:
            users = users.filter(role=role)
        if status_filter:
            users = users.filter(status=status_filter)
        if search:
            users = users.filter(
                Q(full_name__icontains=search) |
                Q(email__icontains=search) |
                Q(phone_number__icontains=search)
            )

        users = users.order_by('-created_at')
        serializer = UserSerializer(users, many=True, context={'request': request})

        return Response({'success': True, 'count': users.count(), 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_user_detail(request, user_id):
    try:
        user = User.objects.get(user_id=user_id)

        if request.method == 'GET':
            serializer = UserSerializer(user, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'PUT':
            serializer = UserSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'User updated successfully',
                    'data': serializer.data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except User.DoesNotExist:
        return Response({'success': False, 'message': 'User not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_block_user(request, user_id):
    """Block/unblock user"""
    try:
        user = User.objects.get(user_id=user_id)
        action = request.data.get('action')

        if action == 'block':
            user.status = 'suspended'
            user.is_active = False
            message = 'User blocked successfully'
        elif action == 'unblock':
            user.status = 'active'
            user.is_active = True
            message = 'User unblocked successfully'
        else:
            return Response({
                'success': False,
                'message': 'Invalid action. Use "block" or "unblock"'
            }, status=status.HTTP_400_BAD_REQUEST)

        user.save()

        AdminLog.objects.create(
            admin_user=request.user,
            action_type=f'USER_{action.upper()}',
            target_id=user.user_id,
            details=f'{action}ed user {user.full_name}'
        )

        return Response({'success': True, 'message': message})

    except User.DoesNotExist:
        return Response({'success': False, 'message': 'User not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN KYC ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_pending_kyc(request):
    try:
        documents = KYCDocument.objects.filter(verification_status='pending')
        serializer = KYCDocumentSerializer(documents, many=True, context={'request': request})
        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_verify_kyc(request, doc_id):
    try:
        document = KYCDocument.objects.get(doc_id=doc_id)
        action = request.data.get('action')
        rejection_reason = request.data.get('rejection_reason')

        if action == 'approve':
            document.verification_status = 'approved'
            document.rejection_reason = None

            user = document.user
            all_docs = KYCDocument.objects.filter(user=user)
            if all_docs.filter(verification_status='approved').count() >= 2:
                user.is_verified = True
                user.save()

        elif action == 'reject':
            document.verification_status = 'rejected'
            document.rejection_reason = rejection_reason
        else:
            return Response({'success': False, 'message': 'Invalid action. Use "approve" or "reject"'},
                            status=status.HTTP_400_BAD_REQUEST)

        document.save()

        AdminLog.objects.create(
            admin_user=request.user,
            action_type=f'KYC_{action.upper()}',
            target_id=document.user.user_id,
            details=f'{action}d {document.document_type} document'
        )

        return Response({'success': True, 'message': f'KYC document {action}d successfully'})

    except KYCDocument.DoesNotExist:
        return Response({'success': False, 'message': 'Document not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN VEHICLES ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_pending_vehicles(request):
    try:
        vehicles = Vehicle.objects.filter(verification_status='pending')
        serializer = VehicleSerializer(vehicles, many=True, context={'request': request})
        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_verify_vehicle(request, vehicle_id):
    try:
        vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)
        action = request.data.get('action')

        if action == 'verify':
            vehicle.verification_status = 'verified'
        elif action == 'reject':
            vehicle.verification_status = 'rejected'
        else:
            return Response({'success': False, 'message': 'Invalid action. Use "verify" or "reject"'},
                            status=status.HTTP_400_BAD_REQUEST)

        vehicle.save()

        AdminLog.objects.create(
            admin_user=request.user,
            action_type=f'VEHICLE_{action.upper()}',
            target_id=vehicle.vehicle_id,
            details=f'{action}d vehicle {vehicle.registration_number}'
        )

        return Response({'success': True, 'message': f'Vehicle {action}d successfully'})

    except Vehicle.DoesNotExist:
        return Response({'success': False, 'message': 'Vehicle not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN DISPUTES ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_disputes(request):
    """View all disputes (admin only)"""
    try:
        status_filter = request.GET.get('status')
        disputes = Dispute.objects.all()
        if status_filter:
            disputes = disputes.filter(status=status_filter)

        disputes = disputes.order_by('-created_at')
        serializer = DisputeSerializer(disputes, many=True)

        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_update_dispute(request, dispute_id):
    """Update dispute status (admin only)"""
    try:
        dispute = Dispute.objects.get(dispute_id=dispute_id)
        status_update = request.data.get('status')
        admin_notes = request.data.get('admin_notes')

        if status_update:
            dispute.status = status_update
        if admin_notes:
            dispute.admin_notes = admin_notes

        dispute.save()

        AdminLog.objects.create(
            admin_user=request.user,
            action_type='DISPUTE_UPDATE',
            target_id=dispute.dispute_id,
            details=f'Updated dispute status to {status_update}'
        )

        return Response({
            'success': True,
            'message': 'Dispute updated successfully',
            'data': DisputeSerializer(dispute).data
        })

    except Dispute.DoesNotExist:
        return Response({'success': False, 'message': 'Dispute not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN LOGS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_logs(request):
    """View admin activity logs"""
    try:
        logs = AdminLog.objects.all().order_by('-created_at')[:100]
        serializer = AdminLogSerializer(logs, many=True)

        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)