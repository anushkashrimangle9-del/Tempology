from django.urls import path
from . import views

urlpatterns = [
    # Authentication URLs
    path('auth/register/', views.register_view, name='register'),
    path('auth/login/email/', views.login_with_email_view, name='login-email'),
    path('auth/login/phone/', views.login_with_phone_view, name='login-phone'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/refresh/', views.refresh_token_view, name='refresh-token'),

    # OTP URLs
    path('auth/otp/send/', views.send_otp_view, name='send-otp'),
    path('auth/otp/verify/', views.verify_otp_view, name='verify-otp'),

    # Password Management
    path('auth/password/forgot/', views.forgot_password_view, name='forgot-password'),
    path('auth/password/reset/', views.reset_password_view, name='reset-password'),
    path('auth/password/change/', views.change_password_view, name='change-password'),

    # Profile
    path('profile/', views.profile_view, name='profile'),
    path('dashboard/', views.dashboard_view, name='dashboard'),


    # ============ KYC ============
    path('kyc/my-documents/', views.my_kyc_documents, name='my_kyc_documents'),
    path('kyc/documents/<int:doc_id>/', views.kyc_document_detail, name='kyc_document_detail'),

    # ============ ADDRESSES ============
    path('addresses/', views.my_addresses, name='my_addresses'),
    path('addresses/<int:address_id>/', views.address_detail, name='address_detail'),

    # ============ CORPORATE ============
    path('corporate/profile/', views.corporate_profile, name='corporate_profile'),

    # ============ VEHICLES ============
    path('vehicles/', views.my_vehicles, name='my_vehicles'),
    path('vehicles/<int:vehicle_id>/', views.vehicle_detail, name='vehicle_detail'),

    # ============ VEHICLE SCHEDULES ============
    path('schedules/', views.my_schedules, name='my_schedules'),
    path('schedules/<int:schedule_id>/', views.schedule_detail, name='schedule_detail'),

    # ============ LOADS ============
    path('loads/', views.my_loads, name='my_loads'),
    path('loads/<int:load_id>/', views.load_detail, name='load_detail'),
    path('loads/search/', views.search_loads, name='search_loads'),

    # ============ BIDS ============
    path('bids/', views.my_bids, name='my_bids'),
    path('bids/load/<int:load_id>/', views.load_bids, name='load_bids'),
    path('bids/<int:bid_id>/accept/', views.accept_bid, name='accept_bid'),

    # ============ BOOKINGS ============
    path('bookings/', views.my_bookings, name='my_bookings'),
    path('bookings/<int:booking_id>/', views.booking_detail, name='booking_detail'),
    path('bookings/<int:booking_id>/verify-otp/', views.verify_booking_otp, name='verify_booking_otp'),

    # ============ TRACKING ============
    path('tracking/update/', views.update_tracking, name='update_tracking'),
    path('tracking/<int:booking_id>/', views.get_tracking, name='get_tracking'),

    # ============ WALLET ============
    path('wallet/', views.my_wallet, name='my_wallet'),
    path('wallet/transactions/', views.wallet_transactions, name='wallet_transactions'),

    # ============ RATINGS ============
    path('ratings/', views.my_ratings, name='my_ratings'),

    # ============ DISPUTES ============
    path('disputes/', views.my_disputes, name='my_disputes'),

    # ============ NOTIFICATIONS ============
    path('notifications/', views.my_notifications, name='my_notifications'),
    path('notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),

    # ============ DASHBOARD ============
    path('dashboard/', views.dashboard_summary, name='dashboard_summary'),

    # ============ ADMIN ============
    path('admin/users/', views.admin_users_list, name='admin_users_list'),
    path('admin/users/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),
    path('admin/kyc/pending/', views.admin_pending_kyc, name='admin_pending_kyc'),
    path('admin/kyc/<int:doc_id>/verify/', views.admin_verify_kyc, name='admin_verify_kyc'),
    path('admin/vehicles/pending/', views.admin_pending_vehicles, name='admin_pending_vehicles'),
    path('admin/vehicles/<int:vehicle_id>/verify/', views.admin_verify_vehicle, name='admin_verify_vehicle'),
]