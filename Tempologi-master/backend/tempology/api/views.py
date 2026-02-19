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

from .models import *
from .serializers import *
from .permission import *


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

from .models import *
from .serializers import *
from .permission import *


# ============ UTILITY FUNCTIONS ============
def generate_otp():
    """Generate 6-digit OTP"""
    return str(random.randint(100000, 999999))


def send_otp(contact, contact_type, otp, otp_type):
    """
    Send OTP via Email or SMS
    Mock function - replace with actual email/SMS service
    """
    if contact_type == 'email':
        print(f"Email OTP {otp} sent to {contact} for {otp_type}")
        # TODO: Integrate with actual email service
        return True
    else:
        print(f"SMS OTP {otp} sent to {contact} for {otp_type}")
        # TODO: Integrate with actual SMS service
        return True


# ============ REGISTRATION VIEWS (TWO-STEP VERIFICATION) ============
@api_view(['POST'])
@permission_classes([AllowAny])
def register_init_view(request):
    """
    Step 1: Initialize registration - validate user data
    This doesn't create user, just validates and prepares for OTP sending
    """
    try:
        serializer = RegistrationInitSerializer(data=request.data)

        if serializer.is_valid():
            # Store validated data in session or return for client to store
            # For simplicity, we'll just return success and let client store temporarily
            return Response({
                'success': True,
                'message': 'Validation successful. Please verify your email and phone.',
                'data': {
                    'email': serializer.validated_data['email'],
                    'phone_number': serializer.validated_data['phone_number'],
                    'requires_verification': True
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
def send_registration_otp_view(request):
    """
    Send OTP for email or phone during registration
    """
    try:
        serializer = SendOTPSerializer(data=request.data)

        if serializer.is_valid():
            contact = serializer.validated_data['contact']
            contact_type = serializer.validated_data['contact_type']
            otp_type = serializer.validated_data['otp_type']

            # Generate OTP
            otp = generate_otp()

            # Invalidate old unverified OTPs for this contact and type
            filter_kwargs = {
                'otp_type': otp_type,
                'is_used': False,
                'is_verified': False
            }

            if contact_type == 'email':
                filter_kwargs['email'] = contact
            else:
                filter_kwargs['phone_number'] = contact

            OTP.objects.filter(**filter_kwargs).update(is_used=True)  # Mark old as used

            # Create new OTP
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

            # Send OTP
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

            # Include OTP in response for testing only
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
def verify_registration_otp_view(request):
    """
    Verify OTP for email or phone during registration
    This marks OTP as verified but not used
    """
    try:
        serializer = VerifyOTPSerializer(data=request.data)

        if serializer.is_valid():
            otp_instance = serializer.validated_data['otp_instance']

            # Mark as verified but not used (will be used during final registration)
            otp_instance.is_verified = True
            otp_instance.save()

            contact = otp_instance.email or otp_instance.phone_number
            contact_type = 'email' if otp_instance.email else 'phone'

            return Response({
                'success': True,
                'message': f'{contact_type.capitalize()} OTP verified successfully',
                'data': {
                    'verified': True,
                    'contact': contact,
                    'contact_type': contact_type
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
def complete_registration_view(request):
    """
    Step 3: Complete registration after both OTPs are verified
    """
    try:
        serializer = CompleteRegistrationSerializer(data=request.data)

        if serializer.is_valid():
            with transaction.atomic():
                email = serializer.validated_data['email']
                phone = serializer.validated_data['phone_number']

                # Get and mark email OTP as used
                email_otp = OTP.objects.filter(
                    email=email,
                    otp_type='email_registration',
                    is_verified=True,
                    is_used=False
                ).latest('created_at')
                email_otp.is_used = True
                email_otp.save()

                # Get and mark phone OTP as used
                phone_otp = OTP.objects.filter(
                    phone_number=phone,
                    otp_type='phone_registration',
                    is_verified=True,
                    is_used=False
                ).latest('created_at')
                phone_otp.is_used = True
                phone_otp.save()

                # Create user
                user = User.objects.create_user(
                    phone_number=phone,
                    full_name=serializer.validated_data['full_name'],
                    role=serializer.validated_data['role'],
                    email=email,
                    password=serializer.validated_data['password'],
                    is_verified=True  # Both email and phone verified
                )

                # Create wallet
                try:
                    Wallet.objects.get_or_create(user=user)
                except Exception as e:
                    print(f"Wallet creation error: {e}")

                # Generate tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                refresh['role'] = user.role
                refresh['email'] = user.email
                refresh['name'] = user.full_name

                # Send welcome notification
                create_notification(
                    user,
                    'Welcome to TempoLogi',
                    f'Welcome {user.full_name}! Your account has been created successfully with email and phone verified.',
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

    except OTP.DoesNotExist:
        return Response({
            'success': False,
            'message': 'OTP verification records not found. Please verify both email and phone first.'
        }, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ LOGIN VIEW (Email only, no verification needed) ============
@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_email_view(request):
    """Login with email and password - NO OTP REQUIRED"""
    try:
        serializer = EmailLoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

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


# ============ PASSWORD RESET VIEWS ============
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_view(request):
    """Send OTP to email for password reset"""
    try:
        serializer = ForgotPasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']
            email = user.email

            # Generate OTP
            otp = generate_otp()

            # Invalidate old OTPs
            OTP.objects.filter(
                email=email,
                otp_type='password_reset',
                is_used=False
            ).update(is_used=True)

            # Create new OTP
            OTP.objects.create(
                email=email,
                otp=otp,
                otp_type='password_reset',
                expires_at=timezone.now() + timedelta(minutes=5)
            )

            # Send OTP via email
            send_otp(email, 'email', otp, 'password_reset')

            response_data = {
                'success': True,
                'message': 'OTP sent for password reset to your email',
                'data': {
                    'email': email,
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

            user.set_password(serializer.validated_data['new_password'])
            user.save()

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
@permission_classes([IsAuthenticated, IsActiveUser])
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
@permission_classes([IsAuthenticated, IsActiveUser])
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
                'open_disputes': Dispute.objects.filter(status__in=['open', 'investigating']).count(),
                'escrow_balance': Payment.objects.filter(payment_status='escrow_held').aggregate(Sum('amount'))['amount__sum'] or 0
            }

        try:
            wallet = Wallet.objects.get(user=user)
            summary['wallet_balance'] = float(wallet.balance)
        except Wallet.DoesNotExist:
            summary['wallet_balance'] = 0

        # Add unread notifications count
        summary['unread_notifications'] = Notification.objects.filter(user=user, is_read=False).count()

        return Response({
            'success': True,
            'data': summary
        })

    except Exception as e:
        return Response({
            'success': False,
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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


# ============ VEHICLE AVAILABILITY VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser, IsVehicleOwner])
def vehicle_availability(request, vehicle_id):
    try:
        vehicle = Vehicle.objects.get(vehicle_id=vehicle_id)

        if request.method == 'GET':
            # Get availability status - return active schedules
            schedules = VehicleSchedule.objects.filter(vehicle=vehicle, status='active')
            serializer = VehicleScheduleSerializer(schedules, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            # Set availability
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


# ============ RETURN TRIP SCHEDULE VIEWS ============
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

            # Set trip_type as 'return' for return trips
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
@permission_classes([IsAuthenticated, IsActiveUser, IsLoadOwner])
def load_detail(request, load_id):
    try:
        load = Load.objects.get(load_id=load_id)

        if request.method == 'GET':
            # Allow anyone to view load details, but restrict modifications
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


# ============ SMART MATCHING ENGINE ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsTruckOwnerOrTransporter, IsActiveUser])
def search_loads(request):
    """Search for loads matching vehicle availability (for truck owners/transporters)"""
    try:
        loads = Load.objects.filter(status='open', pickup_date__gte=timezone.now())

        # Get user's vehicles for matching
        vehicles = Vehicle.objects.filter(owner=request.user, is_active=True)

        vehicle_type = request.GET.get('vehicle_type')
        if vehicle_type:
            loads = loads.filter(required_vehicle_type=vehicle_type)

        min_weight = request.GET.get('min_weight')
        if min_weight:
            loads = loads.filter(weight_kg__gte=min_weight)

        # Match based on return trip schedules
        return_trip_only = request.GET.get('return_trip_only', 'false').lower() == 'true'
        if return_trip_only:
            # Get vehicle schedules for return trips
            schedules = VehicleSchedule.objects.filter(
                vehicle__in=vehicles,
                trip_type='return',
                status='active',
                available_from__lte=timezone.now(),
                available_to__gte=timezone.now()
            )
            if schedules.exists():
                # This is simplified - in production you'd do more sophisticated matching
                loads = loads.filter(
                    Q(pickup_address__icontains=schedules[0].start_location) |
                    Q(drop_address__icontains=schedules[0].end_location)
                )

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
    """Search for available vehicles (for consignees)"""
    try:
        vehicles = Vehicle.objects.filter(is_active=True, verification_status='verified')

        vehicle_type = request.GET.get('vehicle_type')
        if vehicle_type:
            vehicles = vehicles.filter(vehicle_type=vehicle_type)

        min_capacity = request.GET.get('min_capacity')
        if min_capacity:
            vehicles = vehicles.filter(capacity_ton__gte=min_capacity)

        # Get location from request
        location = request.GET.get('location')
        if location:
            # Find vehicles with schedules matching location
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


# ============ BID VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
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
@permission_classes([IsAuthenticated, IsActiveUser, IsLoadOwner])
def load_bids(request, load_id):
    try:
        load = Load.objects.get(load_id=load_id)

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
@permission_classes([IsAuthenticated, IsActiveUser, IsLoadOwner])
def accept_bid(request, bid_id):
    try:
        with transaction.atomic():
            bid = Bid.objects.select_for_update().get(bid_id=bid_id)

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

            # Calculate taxes (18% GST as example)
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

            # Create payment with escrow
            Payment.objects.create(
                booking=booking,
                payer=load.consignee,
                payee=bid.transporter,
                amount=total_amount,
                payment_gateway='wallet',
                payment_status='escrow_held',  # Held in escrow until delivery
                admin_commission=bid.bid_amount * 0.05,  # 5% platform fee
                vendor_payout=bid.bid_amount * 0.95
            )

            # Create notifications
            create_notification(
                bid.transporter,
                'Bid Accepted',
                f'Your bid for load #{load.load_id} has been accepted. Booking created.',
                'booking'
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
@permission_classes([IsAuthenticated, IsActiveUser])
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
@permission_classes([IsAuthenticated, IsActiveUser, IsBookingParticipant])
def booking_detail(request, booking_id):
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        if request.method == 'GET':
            serializer = BookingSerializer(booking)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'PUT':
            # Only transporter or admin can update booking details
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
def upload_booking_document(request, booking_id):
    """Upload invoice or bilty for booking"""
    try:
        booking = Booking.objects.get(booking_id=booking_id)

        doc_type = request.data.get('doc_type')  # 'invoice' or 'bilty'
        file_url = request.data.get('file_url')

        if not doc_type or not file_url:
            return Response({
                'success': False,
                'message': 'doc_type and file_url are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        if doc_type == 'invoice':
            booking.invoice_url = file_url
        elif doc_type == 'bilty':
            booking.bilty_url = file_url
        else:
            return Response({
                'success': False,
                'message': 'Invalid document type. Use "invoice" or "bilty"'
            }, status=status.HTTP_400_BAD_REQUEST)

        booking.save()

        return Response({
            'success': True,
            'message': f'{doc_type} uploaded successfully'
        })

    except Booking.DoesNotExist:
        return Response({'success': False, 'message': 'Booking not found'},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsActiveUser, IsBookingParticipant])
def verify_booking_otp(request, booking_id):
    try:
        booking = Booking.objects.get(booking_id=booking_id)

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

            # Release payment from escrow
            payment = Payment.objects.filter(booking=booking).first()
            if payment:
                payment.payment_status = 'released_to_vendor'
                payment.released_at = timezone.now()
                payment.save()

                # Credit vendor wallet
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

                    create_notification(
                        payment.payee,
                        'Payment Released',
                        f'Payment of ₹{payment.vendor_payout} has been released for booking #{booking.booking_id}',
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

        # Only transporter or driver can update tracking
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

        # Check if user is participant
        if request.user not in [booking.consignee, booking.transporter, booking.driver] and request.user.role != 'admin':
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

        # In production, integrate with payment gateway here
        wallet.balance += float(amount)
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


# ============ PAYMENT VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsActiveUser])
def my_payments(request):
    try:
        user = request.user
        payments = Payment.objects.filter(Q(payer=user) | Q(payee=user)).order_by('-created_at')
        serializer = PaymentSerializer(payments, many=True)
        return Response({'success': True, 'data': serializer.data})

    except Exception as e:
        return Response({'success': False, 'message': str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============ RATING VIEWS ============
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated, IsActiveUser])
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
            # Check if booking is completed before rating
            booking_id = request.data.get('booking')
            try:
                booking = Booking.objects.get(booking_id=booking_id)
                if booking.booking_status != 'completed':
                    return Response({
                        'success': False,
                        'message': 'You can only rate completed bookings'
                    }, status=status.HTTP_400_BAD_REQUEST)
            except Booking.DoesNotExist:
                pass

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
@permission_classes([IsAuthenticated, IsActiveUser])
def my_disputes(request):
    try:
        if request.method == 'GET':
            disputes = Dispute.objects.filter(raised_by=request.user)
            serializer = DisputeSerializer(disputes, many=True)
            return Response({'success': True, 'data': serializer.data})

        elif request.method == 'POST':
            # Check if user is participant in the booking
            booking_id = request.data.get('booking')
            try:
                booking = Booking.objects.get(booking_id=booking_id)
                if request.user not in [booking.consignee, booking.transporter, booking.driver]:
                    return Response({
                        'success': False,
                        'message': 'You can only file disputes for bookings you are part of'
                    }, status=status.HTTP_403_FORBIDDEN)
            except Booking.DoesNotExist:
                return Response({
                    'success': False,
                    'message': 'Booking not found'
                }, status=status.HTTP_404_NOT_FOUND)

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


# ============ ADMIN VIEWS ============
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
        action = request.data.get('action')  # 'block' or 'unblock'

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
        action = request.data.get('action')  # 'approve' or 'reject'
        rejection_reason = request.data.get('rejection_reason')

        if action == 'approve':
            document.verification_status = 'approved'
            document.rejection_reason = None

            # Check if all KYC documents are approved
            user = document.user
            all_docs = KYCDocument.objects.filter(user=user)
            if all_docs.filter(verification_status='approved').count() >= 2:  # At least 2 docs approved
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


# ============ REPORTS & ANALYTICS VIEWS ============
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_reports(request):
    """Generate reports (admin only)"""
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

        if report_type == 'utilization':
            # Vehicle utilization report
            vehicles = Vehicle.objects.all()
            data = []
            for vehicle in vehicles:
                bookings = Booking.objects.filter(
                    vehicle=vehicle,
                    created_at__range=[start_date, end_date]
                )
                total_trips = bookings.count()
                data.append({
                    'vehicle_id': vehicle.vehicle_id,
                    'registration_number': vehicle.registration_number,
                    'owner': vehicle.owner.full_name,
                    'total_trips': total_trips,
                    'total_earnings': bookings.aggregate(Sum('agreed_price'))['agreed_price__sum'] or 0
                })

            return Response({'success': True, 'data': data})

        elif report_type == 'revenue':
            # Revenue report
            payments = Payment.objects.filter(
                created_at__range=[start_date, end_date],
                payment_status='released_to_vendor'
            )

            total_revenue = payments.aggregate(Sum('admin_commission'))['admin_commission__sum'] or 0
            total_payouts = payments.aggregate(Sum('vendor_payout'))['vendor_payout__sum'] or 0
            total_transactions = payments.count()

            popular_routes = Load.objects.filter(
                created_at__range=[start_date, end_date]
            ).values('pickup_address', 'drop_address').annotate(
                count=Count('load_id')
            ).order_by('-count')[:10]

            return Response({
                'success': True,
                'data': {
                    'total_revenue': total_revenue,
                    'total_payouts': total_payouts,
                    'total_transactions': total_transactions,
                    'popular_routes': list(popular_routes)
                }
            })

        elif report_type == 'environmental':
            # Environmental impact report (empty miles saved)
            loads = Load.objects.filter(
                created_at__range=[start_date, end_date],
                status='delivered'
            )
            total_weight = loads.aggregate(Sum('weight_kg'))['weight_kg__sum'] or 0

            # Simplified calculation - in production, use actual route distances
            estimated_km_saved = loads.count() * 50  # Assume average 50km saved per trip
            diesel_saved = estimated_km_saved * 0.25  # 0.25L per km
            co2_saved = diesel_saved * 2.68  # 2.68kg CO2 per liter diesel

            return Response({
                'success': True,
                'data': {
                    'total_trips': loads.count(),
                    'total_weight_kg': total_weight,
                    'empty_km_saved': estimated_km_saved,
                    'diesel_saved_liters': diesel_saved,
                    'co2_saved_kg': co2_saved
                }
            })

        elif report_type == 'users':
            # User statistics
            total_users = User.objects.filter(created_at__range=[start_date, end_date]).count()
            users_by_role = User.objects.filter(created_at__range=[start_date, end_date]).values('role').annotate(count=Count('role'))
            verified_users = User.objects.filter(is_verified=True, created_at__range=[start_date, end_date]).count()

            return Response({
                'success': True,
                'data': {
                    'total_users': total_users,
                    'verified_users': verified_users,
                    'users_by_role': list(users_by_role)
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


# ============ ADMIN LOGS VIEW ============
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