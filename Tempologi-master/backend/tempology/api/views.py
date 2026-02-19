from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status

from django.db import transaction
from django.db.models import Q, Count, Sum
from django.utils import timezone
from datetime import timedelta
import random
import uuid
from .serializers import *
from .permission import *
from .models import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Q, Count, Sum
from django.utils import timezone
from datetime import timedelta
import random
import uuid

from .models import *
from .serializers import *


# ============ UTILITY FUNCTIONS ============
def generate_session_id():
    return str(uuid.uuid4())


def generate_otp():
    return str(random.randint(1000, 9999))


def send_otp_email(email, otp, otp_type):
    """Mock function to send OTP via Email"""
    print(f"Email OTP {otp} sent to {email} for {otp_type}")
    # In production, integrate with actual email service
    return True


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


# ============ REGISTRATION VIEW ============
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """Register a new user"""
    try:
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            with transaction.atomic():
                # Create user
                user = User.objects.create_user(
                    phone_number=serializer.validated_data['phone_number'],
                    full_name=serializer.validated_data['full_name'],
                    role=serializer.validated_data['role'],
                    email=serializer.validated_data['email'],
                    password=serializer.validated_data['password'],
                    is_verified=True  # Auto-verify for simplicity, add email verification if needed
                )

                # Create wallet
                try:
                    Wallet.objects.get_or_create(user=user)
                except Exception as e:
                    print(f"Wallet creation error: {e}")

                # Generate tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                # Add custom claims
                refresh['role'] = user.role
                refresh['email'] = user.email
                refresh['name'] = user.full_name

                # Create welcome notification
                create_notification(
                    user,
                    'Welcome to TempoLogi',
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

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ LOGIN VIEWS ============
@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_email_view(request):
    """Login with email and password"""
    try:
        serializer = EmailLoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Add custom claims
            refresh['role'] = user.role
            refresh['email'] = user.email
            refresh['name'] = user.full_name

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

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_phone_view(request):
    """Login with phone number and password"""
    try:
        serializer = PhoneLoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            # Add custom claims
            refresh['role'] = user.role
            refresh['email'] = user.email
            refresh['name'] = user.full_name

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

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ OTP VIEWS ============
@api_view(['POST'])
@permission_classes([AllowAny])
def send_otp_view(request):
    """Send OTP for email verification or password reset"""
    try:
        serializer = SendOTPSerializer(data=request.data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_type = serializer.validated_data['otp_type']

            # Check if email exists for password reset
            if otp_type == 'password_reset':
                if not User.objects.filter(email=email).exists():
                    return Response({
                        'success': False,
                        'message': 'No account found with this email'
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Generate OTP
            otp = generate_otp()

            # Invalidate previous unused OTPs
            OTP.objects.filter(
                email=email,
                otp_type=otp_type,
                is_used=False
            ).update(is_used=True)

            # Create new OTP
            OTP.objects.create(
                email=email,
                otp=otp,
                otp_type=otp_type,
                expires_at=timezone.now() + timedelta(minutes=10)
            )

            # Send OTP via email
            send_otp_email(email, otp, otp_type)

            response_data = {
                'success': True,
                'message': 'OTP sent successfully',
                'data': {
                    'email': email,
                    'otp_type': otp_type,
                    'expires_in': 600
                }
            }

            # Include OTP in response for testing
            if getattr(settings, 'DEBUG', False):
                response_data['data']['test_otp'] = otp

            return Response(response_data)

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp_view(request):
    """Verify OTP"""
    try:
        serializer = VerifyOTPSerializer(data=request.data)

        if serializer.is_valid():
            otp_instance = serializer.validated_data['otp_instance']

            # Mark OTP as used
            otp_instance.is_used = True
            otp_instance.save()

            return Response({
                'success': True,
                'message': 'OTP verified successfully',
                'data': {
                    'verified': True
                }
            })

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ PASSWORD MANAGEMENT VIEWS ============
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_view(request):
    """Send OTP for password reset"""
    try:
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Generate OTP
            otp = generate_otp()

            # Invalidate previous OTPs
            OTP.objects.filter(
                email=user.email,
                otp_type='password_reset',
                is_used=False
            ).update(is_used=True)

            # Create OTP
            OTP.objects.create(
                email=user.email,
                otp=otp,
                otp_type='password_reset',
                expires_at=timezone.now() + timedelta(minutes=5)
            )

            # Send OTP
            send_otp_email(user.email, otp, 'password_reset')

            response_data = {
                'success': True,
                'message': 'OTP sent for password reset',
                'data': {
                    'email': user.email,
                    'expires_in': 300
                }
            }

            if getattr(settings, 'DEBUG', False):
                response_data['data']['test_otp'] = otp

            return Response(response_data)

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_view(request):
    """Reset password with OTP"""
    try:
        serializer = ResetPasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            otp_obj = serializer.validated_data['otp_instance']

            # Update password
            user.set_password(serializer.validated_data['new_password'])
            user.save()

            # Mark OTP as used
            otp_obj.is_used = True
            otp_obj.save()

            return Response({
                'success': True,
                'message': 'Password reset successful'
            })

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password_view(request):
    """Change user password"""
    try:
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data['new_password'])
            user.save()

            return Response({
                'success': True,
                'message': 'Password changed successfully'
            })

        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ TOKEN MANAGEMENT VIEWS ============
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    """Logout user - blacklist refresh token"""
    try:
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e:
                print(f"Token blacklist error: {e}")

        return Response({
            'success': True,
            'message': 'Logout successful'
        })
    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
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
        }, status=status.HTTP_401_UNAUTHORIZED)


# ============ PROFILE VIEWS ============
@api_view(['GET', 'PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    """Get or update user profile"""
    try:
        if request.method == 'GET':
            serializer = UserSerializer(request.user, context={'request': request})
            return Response({
                'success': True,
                'data': serializer.data
            })

        elif request.method in ['PUT', 'PATCH']:
            serializer = ProfileUpdateSerializer(
                request.user,
                data=request.data,
                partial=True,
                context={'request': request}
            )
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'data': UserSerializer(request.user, context={'request': request}).data
                })
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ DASHBOARD VIEW ============
@api_view(['GET'])
@permission_classes([IsAuthenticated])
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
            }

        elif user.role in ['truck_owner', 'transporter']:
            vehicles = Vehicle.objects.filter(owner=user)
            bookings = Booking.objects.filter(transporter=user)
            bids = Bid.objects.filter(transporter=user)

            summary = {
                'total_vehicles': vehicles.count(),
                'active_vehicles': vehicles.filter(is_active=True).count(),
                'pending_verifications': vehicles.filter(verification_status='pending').count(),
                'pending_bids': bids.filter(bid_status='pending').count(),
                'active_bookings': bookings.filter(
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']
                ).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
            }

        elif user.role == 'driver':
            bookings = Booking.objects.filter(driver=user)
            summary = {
                'active_bookings': bookings.filter(
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']
                ).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
            }

        elif user.role == 'admin':
            summary = {
                'total_users': User.objects.count(),
                'total_vehicles': Vehicle.objects.count(),
                'total_loads': Load.objects.count(),
                'total_bookings': Booking.objects.count(),
                'pending_kyc': KYCDocument.objects.filter(verification_status='pending').count(),
                'pending_vehicle_verifications': Vehicle.objects.filter(verification_status='pending').count(),
            }

        # Add wallet balance
        try:
            wallet = Wallet.objects.get(user=user)
            summary['wallet_balance'] = float(wallet.balance)
        except Wallet.DoesNotExist:
            summary['wallet_balance'] = 0

        return Response({
            'success': True,
            'data': summary
        })

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Rest of your views (KYC, Address, Vehicle, Load, Bid, Booking, etc.) remain the same...
@api_view(['GET', 'PUT', 'PATCH'])
@permission_classes([IsAuthenticated])
def profile(request):
    try:
        if request.method == 'GET':
            serializer = UserSerializer(request.user, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = UserSerializer(
                request.user,
                data=request.data,
                partial=True,
                context={'request': request}
            )
            if serializer.is_valid():
                serializer.save()
                return Response({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'data': serializer.data
                })
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)




# ============ KYC DOCUMENT VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
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
@permission_classes([IsAuthenticated])
def kyc_document_detail(request, doc_id):
    try:
        document = KYCDocument.objects.get(doc_id=doc_id, user=request.user)

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
@permission_classes([IsAuthenticated])
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
@permission_classes([IsAuthenticated])
def address_detail(request, address_id):
    try:
        address = SavedAddress.objects.get(address_id=address_id, user=request.user)

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
@permission_classes([IsAuthenticated])
def corporate_profile(request):
    try:
        if request.user.role != 'corporate':
            return Response({
                'success': False,
                'message': 'Only corporate users can access this'
            }, status=status.HTTP_403_FORBIDDEN)

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
@permission_classes([IsAuthenticated])
def my_vehicles(request):
    try:
        if request.user.role not in ['truck_owner', 'transporter']:
            return Response({
                'success': False,
                'message': 'Only truck owners and transporters can access this'
            }, status=status.HTTP_403_FORBIDDEN)

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
@permission_classes([IsAuthenticated])
def vehicle_detail(request, vehicle_id):
    try:
        vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)

        # Check ownership
        if vehicle.owner != request.user:
            return Response({
                'success': False,
                'message': 'You do not have permission to access this vehicle'
            }, status=status.HTTP_403_FORBIDDEN)

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


# ============ VEHICLE SCHEDULE VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def my_schedules(request):
    try:
        if request.user.role not in ['truck_owner', 'transporter']:
            return Response({
                'success': False,
                'message': 'Only truck owners and transporters can access this'
            }, status=status.HTTP_403_FORBIDDEN)

        if request.method == 'GET':
            schedules = VehicleSchedule.objects.filter(vehicle__owner=request.user)
            serializer = VehicleScheduleSerializer(schedules, many=True, context={'request': request})
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = VehicleScheduleSerializer(data=request.data)
            if serializer.is_valid():
                # Ensure the vehicle belongs to the user
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
@permission_classes([IsAuthenticated])
def schedule_detail(request, schedule_id):
    try:
        schedule = VehicleSchedule.objects.get(schedule_id=schedule_id)

        # Check ownership
        if schedule.vehicle.owner != request.user:
            return Response({
                'success': False,
                'message': 'You do not have permission to access this schedule'
            }, status=status.HTTP_403_FORBIDDEN)

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


# ============ LOAD VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def my_loads(request):
    try:
        if request.user.role not in ['consignee', 'corporate']:
            return Response({
                'success': False,
                'message': 'Only consignees and corporate users can access this'
            }, status=status.HTTP_403_FORBIDDEN)

        if request.method == 'GET':
            loads = Load.objects.filter(consignee=request.user)
            serializer = LoadSerializer(loads, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = LoadCreateSerializer(data=request.data)
            if serializer.is_valid():
                load = serializer.save(consignee=request.user)
                return Response({
                    'success': True,
                    'message': 'Load created successfully',
                    'data': LoadSerializer(load).data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def load_detail(request, load_id):
    try:
        load = Load.objects.get(load_id=load_id)

        # Check ownership for write operations
        if request.method in ['PUT', 'PATCH', 'DELETE'] and load.consignee != request.user:
            return Response({
                'success': False,
                'message': 'You do not have permission to modify this load'
            }, status=status.HTTP_403_FORBIDDEN)

        if request.method == 'GET':
            serializer = LoadSerializer(load)
            return Response({'success': True, 'data': serializer.data})

        elif request.method in ['PUT', 'PATCH']:
            serializer = LoadCreateSerializer(load, data=request.data, partial=True)
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
            return Response({
                'success': True,
                'message': 'Load deleted successfully'
            })

    except Load.DoesNotExist:
        return Response({'success': False, 'message': 'Load not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def search_loads(request):
    try:
        if request.user.role not in ['truck_owner', 'transporter']:
            return Response({
                'success': False,
                'message': 'Only truck owners and transporters can search loads'
            }, status=status.HTTP_403_FORBIDDEN)

        loads = Load.objects.filter(status='open', pickup_date__gte=timezone.now())

        vehicle_type = request.GET.get('vehicle_type')
        if vehicle_type:
            loads = loads.filter(required_vehicle_type=vehicle_type)

        min_weight = request.GET.get('min_weight')
        if min_weight:
            loads = loads.filter(weight_kg__gte=min_weight)

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


# ============ BID VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def my_bids(request):
    try:
        if request.method == 'GET':
            if request.user.role in ['transporter', 'truck_owner']:
                bids = Bid.objects.filter(transporter=request.user)
            else:
                bids = Bid.objects.filter(load__consignee=request.user)

            serializer = BidSerializer(bids, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            if request.user.role not in ['transporter', 'truck_owner']:
                return Response({
                    'success': False,
                    'message': 'Only transporters can place bids'
                }, status=status.HTTP_403_FORBIDDEN)

            serializer = BidCreateSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                bid = serializer.save(transporter=request.user)
                return Response({
                    'success': True,
                    'message': 'Bid placed successfully',
                    'data': BidSerializer(bid).data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def load_bids(request, load_id):
    try:
        load = Load.objects.get(load_id=load_id)

        # Check if user is consignee of the load
        if load.consignee != request.user:
            return Response({
                'success': False,
                'message': 'You do not have permission to view bids for this load'
            }, status=status.HTTP_403_FORBIDDEN)

        bids = Bid.objects.filter(load=load).order_by('-bid_amount')
        serializer = BidSerializer(bids, many=True)
        return Response({'success': True, 'data': serializer.data})

    except Load.DoesNotExist:
        return Response({'success': False, 'message': 'Load not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def accept_bid(request, bid_id):
    try:
        with transaction.atomic():
            bid = Bid.objects.select_for_update().get(bid_id=bid_id)

            # Check if user is consignee of the load
            if bid.load.consignee != request.user:
                return Response({
                    'success': False,
                    'message': 'You do not have permission to accept this bid'
                }, status=status.HTTP_403_FORBIDDEN)

            if bid.bid_status != 'pending':
                return Response({
                    'success': False,
                    'message': f'Bid is already {bid.bid_status}'
                }, status=status.HTTP_400_BAD_REQUEST)

            bid.bid_status = 'accepted'
            bid.save()

            load = bid.load
            load.status = 'assigned'
            load.save()

            Bid.objects.filter(load=load, bid_status='pending').update(bid_status='rejected')

            tax_amount = bid.bid_amount * 0.18
            total_amount = bid.bid_amount + tax_amount

            booking = Booking.objects.create(
                load=load,
                consignee=load.consignee,
                transporter=bid.transporter,
                vehicle=bid.vehicle,
                agreed_price=bid.bid_amount,
                tax_amount=tax_amount,
                total_amount=total_amount,
                pickup_otp=str(random.randint(100000, 999999)),
                delivery_otp=str(random.randint(100000, 999999))
            )

            Payment.objects.create(
                booking=booking,
                payer=load.consignee,
                payee=bid.transporter,
                amount=total_amount,
                payment_gateway='wallet',
                payment_status='pending',
                admin_commission=bid.bid_amount * 0.05,
                vendor_payout=bid.bid_amount * 0.95
            )

            return Response({
                'success': True,
                'message': 'Bid accepted, booking created',
                'data': BookingSerializer(booking).data
            })

    except Bid.DoesNotExist:
        return Response({'success': False, 'message': 'Bid not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ BOOKING VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_bookings(request):
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

        bookings = bookings.order_by('-created_at')
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
@permission_classes([IsAuthenticated])
def booking_detail(request, booking_id):
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        # Check if user is participant
        if request.user not in [booking.consignee, booking.transporter, booking.driver]:
            return Response({
                'success': False,
                'message': 'You do not have permission to access this booking'
            }, status=status.HTTP_403_FORBIDDEN)

        if request.method == 'GET':
            serializer = BookingSerializer(booking)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'PUT':
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
@permission_classes([IsAuthenticated])
def verify_booking_otp(request, booking_id):
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        # Check if user is participant
        if request.user not in [booking.consignee, booking.transporter, booking.driver]:
            return Response({
                'success': False,
                'message': 'You do not have permission to verify OTP for this booking'
            }, status=status.HTTP_403_FORBIDDEN)

        otp_type = request.data.get('type')  # 'pickup' or 'delivery'
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

        elif otp_type == 'delivery':
            if booking.delivery_otp != otp:
                return Response({'success': False, 'message': 'Invalid delivery OTP'},
                                status=status.HTTP_400_BAD_REQUEST)
            booking.booking_status = 'completed'
            booking.completed_at = timezone.now()
            booking.save()

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
@permission_classes([IsAuthenticated])
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

        # Check if user is transporter or driver
        if request.user not in [booking.transporter, booking.driver]:
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
@permission_classes([IsAuthenticated])
def get_tracking(request, booking_id):
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        # Check if user is participant
        if request.user not in [booking.consignee, booking.transporter, booking.driver]:
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
@permission_classes([IsAuthenticated])
def my_wallet(request):
    try:
        wallet, created = Wallet.objects.get_or_create(user=request.user)
        serializer = WalletSerializer(wallet)
        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def wallet_transactions(request):
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


# ============ RATING VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def my_ratings(request):
    try:
        if request.method == 'GET':
            given = Rating.objects.filter(reviewer=request.user)
            received = Rating.objects.filter(reviewee=request.user)

            return Response({
                'success': True,
                'data': {
                    'given': RatingSerializer(given, many=True).data,
                    'received': RatingSerializer(received, many=True).data
                }
            })

        elif request.method == 'POST':
            serializer = RatingCreateSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                rating = serializer.save(reviewer=request.user)
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


# ============ DISPUTE VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def my_disputes(request):
    try:
        if request.method == 'GET':
            disputes = Dispute.objects.filter(raised_by=request.user)
            serializer = DisputeSerializer(disputes, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            serializer = DisputeCreateSerializer(data=request.data)
            if serializer.is_valid():
                dispute = serializer.save(raised_by=request.user)
                return Response({
                    'success': True,
                    'message': 'Dispute filed successfully',
                    'data': DisputeSerializer(dispute).data
                }, status=status.HTTP_201_CREATED)
            return Response({'success': False, 'errors': serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ NOTIFICATION VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated])
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
@permission_classes([IsAuthenticated])
def mark_notification_read(request, notification_id):
    try:
        notification = Notification.objects.get(notification_id=notification_id, user=request.user)
        notification.is_read = True
        notification.save()
        return Response({'success': True, 'message': 'Notification marked as read'})

    except Notification.DoesNotExist:
        return Response({'success': False, 'message': 'Notification not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ DASHBOARD VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_summary(request):
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
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
            }

        elif user.role in ['truck_owner', 'transporter']:
            vehicles = Vehicle.objects.filter(owner=user)
            bookings = Booking.objects.filter(transporter=user)
            bids = Bid.objects.filter(transporter=user)

            summary = {
                'total_vehicles': vehicles.count(),
                'active_vehicles': vehicles.filter(is_active=True).count(),
                'pending_verifications': vehicles.filter(verification_status='pending').count(),
                'pending_bids': bids.filter(bid_status='pending').count(),
                'active_bookings': bookings.filter(
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
            }

        elif user.role == 'driver':
            bookings = Booking.objects.filter(driver=user)
            summary = {
                'active_bookings': bookings.filter(
                    booking_status__in=['confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit']).count(),
                'completed_trips': bookings.filter(booking_status='completed').count(),
            }

        elif user.role == 'admin':
            summary = {
                'total_users': User.objects.count(),
                'total_vehicles': Vehicle.objects.count(),
                'total_loads': Load.objects.count(),
                'total_bookings': Booking.objects.count(),
                'pending_kyc': KYCDocument.objects.filter(verification_status='pending').count(),
                'pending_vehicle_verifications': Vehicle.objects.filter(verification_status='pending').count(),
            }

        # Add wallet balance
        try:
            wallet = Wallet.objects.get(user=user)
            summary['wallet_balance'] = wallet.balance
        except Wallet.DoesNotExist:
            summary['wallet_balance'] = 0

        return Response({'success': True, 'data': summary})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ ADMIN VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_users_list(request):
    try:
        if request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)

        role = request.GET.get('role')
        status_filter = request.GET.get('status')

        users = User.objects.all()
        if role:
            users = users.filter(role=role)
        if status_filter:
            users = users.filter(status=status_filter)

        users = users.order_by('-created_at')
        serializer = UserSerializer(users, many=True, context={'request': request})

        return Response({'success': True, 'count': users.count(), 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def admin_user_detail(request, user_id):
    try:
        if request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)

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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_pending_kyc(request):
    try:
        if request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)

        documents = KYCDocument.objects.filter(verification_status='pending')
        serializer = KYCDocumentSerializer(documents, many=True, context={'request': request})
        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_verify_kyc(request, doc_id):
    try:
        if request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)

        document = KYCDocument.objects.get(doc_id=doc_id)
        action = request.data.get('action')  # 'approve' or 'reject'
        rejection_reason = request.data.get('rejection_reason')

        if action == 'approve':
            document.verification_status = 'approved'
            document.rejection_reason = None
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


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_pending_vehicles(request):
    try:
        if request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)

        vehicles = Vehicle.objects.filter(verification_status='pending')
        serializer = VehicleSerializer(vehicles, many=True, context={'request': request})
        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def admin_verify_vehicle(request, vehicle_id):
    try:
        if request.user.role != 'admin':
            return Response({
                'success': False,
                'message': 'Admin access required'
            }, status=status.HTTP_403_FORBIDDEN)

        vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)
        action = request.data.get('action')  # 'verify' or 'reject'

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