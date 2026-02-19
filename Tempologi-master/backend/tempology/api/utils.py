import random

from django.db import models
from datetime import timedelta
from django.utils import timezone
from .models import *
from rest_framework_simplejwt.tokens import RefreshToken


def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))


def create_otp(mobile, email=None, otp_type='registration'):
    """Create OTP entry"""
    otp = generate_otp()
    expires_at = timezone.now() + timedelta(minutes=10)  # OTP valid for 10 minutes

    # Mark old OTPs as used
    OTP.objects.filter(mobile=mobile, otp_type=otp_type, is_used=False).update(is_used=True)

    otp_obj = OTP.objects.create(
        mobile=mobile,
        email=email,
        otp=otp,
        otp_type=otp_type,
        expires_at=expires_at
    )

    return otp_obj, otp


def get_user_tokens(user):
    """Generate JWT tokens for user"""
    refresh = RefreshToken.for_user(user)

    # Add custom claims
    refresh['mobile'] = user.mobile
    refresh['role'] = user.role
    refresh['name'] = user.name

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'expires_in': 3600  # 1 hour in seconds
    }


def get_role_redirect_url(role):
    """Get redirect URL based on user role"""
    redirect_map = {
        'consignee': '/consignee/dashboard',
        'tempo_owner': '/owner/dashboard',
        'corporate_client': '/corporate/dashboard',
        'admin': '/admin/dashboard',
        'transporter': '/transporter/dashboard',
    }
    return redirect_map.get(role, '/dashboard')


# In utils.py, add this function:
def calculate_dashboard_summary(user):
    """Calculate dashboard summary based on user role"""
    if user.role == 'consignee':
        past_trips = Trip.objects.filter(consignee=user, status='completed').count()
        ongoing_trips = Trip.objects.filter(
            consignee=user,
            status__in=['scheduled', 'loading', 'in_transit', 'unloading']
        ).count()
        total_spent = Trip.objects.filter(
            consignee=user,
            status='completed'
        ).aggregate(total=models.Sum('agreed_amount'))['total'] or 0

        return {
            'wallet_balance': 0.00,
            'past_trips_count': past_trips,
            'ongoing_bookings_count': ongoing_trips,
            'total_spent': total_spent
        }

    elif user.role == 'tempo_owner':
        total_vehicles = Vehicle.objects.filter(owner=user).count()
        active_trips = Trip.objects.filter(
            owner=user,
            status__in=['scheduled', 'loading', 'in_transit', 'unloading']
        ).count()
        pending_requests = BookingRequest.objects.filter(
            owner=user,
            status='pending'
        ).count()

        total_earnings = Trip.objects.filter(
            owner=user,
            status='completed'
        ).aggregate(total=models.Sum('agreed_amount'))['total'] or 0

        # Monthly earnings (last 30 days)
        month_ago = timezone.now() - timedelta(days=30)
        monthly_earnings = Trip.objects.filter(
            owner=user,
            status='completed',
            created_at__gte=month_ago
        ).aggregate(total=models.Sum('agreed_amount'))['total'] or 0

        # Vehicle status count
        vehicles = Vehicle.objects.filter(owner=user)
        vehicle_status = {
            'active': vehicles.filter(status='active').count(),
            'inactive': vehicles.filter(status='inactive').count(),
            'maintenance': vehicles.filter(status='maintenance').count(),
            'pending_verification': vehicles.filter(status='pending_verification').count(),
            'rejected': vehicles.filter(status='rejected').count(),
        }

        return {
            'total_vehicles': total_vehicles,
            'active_trips': active_trips,
            'pending_requests': pending_requests,
            'wallet_balance': 0.00,
            'total_earnings': total_earnings,
            'monthly_earnings': monthly_earnings,
            'vehicle_status': vehicle_status
        }

    return {}
