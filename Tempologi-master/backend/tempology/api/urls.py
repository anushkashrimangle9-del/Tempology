from django.urls import path
from . import views

urlpatterns = [
    # ============ AUTHENTICATION ============
    path('auth/register/init/', views.register_init_view, name='register_init'),
    path('auth/register/verify-complete/', views.verify_both_otps_and_register_view, name='verify_complete'),
    path('auth/register/send-otp/', views.send_registration_otp_view, name='send_otp'),
    path('auth/login/', views.login_with_email_view, name='login'),
    path('auth/password/forgot/', views.forgot_password_view, name='forgot-password'),
    path('auth/password/reset/', views.reset_password_view, name='reset-password'),
    path('auth/password/change/', views.change_password_view, name='change-password'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/refresh/', views.refresh_token_view, name='refresh-token'),
    path('auth/me/', views.me_view, name='me'),

    # ============ PROFILE & DASHBOARD ============
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
    path('vehicles/<int:vehicle_id>/availability/', views.vehicle_availability, name='vehicle_availability'),

    # ============ VEHICLE SCHEDULES ============
    path('schedules/', views.my_schedules, name='my_schedules'),
    path('schedules/<int:schedule_id>/', views.schedule_detail, name='schedule_detail'),
    path('schedules/return-trip/', views.create_return_trip_schedule, name='create_return_trip'),

    # ============ LOADS ============
    path('loads/', views.my_loads, name='my_loads'),
    path('loads/<int:load_id>/', views.load_detail, name='load_detail'),
    path('loads/search/', views.search_loads, name='search_loads'),
    path('loads/estimate-price/', views.estimate_load_price, name='estimate_load_price'),
    path('loads/bulk-create/', views.bulk_create_loads, name='bulk_create_loads'),

    # ============ VEHICLE SEARCH ============
    path('vehicles/search/', views.search_available_vehicles, name='search_vehicles'),

    # ============ LOAD REQUESTS ============
    path('load-requests/', views.load_requests, name='load_requests'),
    path('load-requests/<int:request_id>/', views.load_request_detail, name='load_request_detail'),
    path('load-requests/<int:request_id>/withdraw/', views.withdraw_load_request, name='withdraw_load_request'),
    path('load-requests/estimate/', views.get_price_estimate, name='get_price_estimate'),

    # ============ TRIPS ============
    path('trips/create/', views.create_trip, name='create_trip'),
    path('trips/', views.my_trips, name='my_trips'),
    path('trips/<int:trip_id>/', views.trip_detail, name='trip_detail'),
    path('trips/<int:trip_id>/update-location/', views.trip_update_location, name='trip_update_location'),
    path('trips/<int:trip_id>/start/', views.driver_start_trip, name='driver_start_trip'),
    path('trips/<int:trip_id>/halt/', views.driver_mark_halted, name='driver_mark_halted'),
    path('trips/<int:trip_id>/resume/', views.driver_resume_from_halt, name='driver_resume_from_halt'),
    path('trips/search/return/', views.search_return_trips, name='search_return_trips'),

    # ============ BOOKINGS ============
    path('bookings/', views.my_bookings, name='my_bookings'),
    path('bookings/<int:booking_id>/', views.booking_detail, name='booking_detail'),
    path('bookings/<int:booking_id>/add-charge/', views.add_extra_charge, name='add_extra_charge'),
    path('bookings/charges/<int:charge_id>/', views.remove_extra_charge, name='remove_extra_charge'),
    path('bookings/<int:booking_id>/verify-otp/', views.verify_booking_otp, name='verify_booking_otp'),

    # ============ TRACKING ============
    path('tracking/update/', views.update_tracking, name='update_tracking'),
    path('tracking/<int:booking_id>/', views.get_tracking, name='get_tracking'),

    # ============ WALLET ============
    path('wallet/', views.my_wallet, name='my_wallet'),
    path('wallet/transactions/', views.wallet_transactions, name='wallet_transactions'),
    path('wallet/add/', views.add_wallet_money, name='add_wallet_money'),
    path('wallet/calculate-consumption/', views.calculate_wallet_consumption, name='calculate_wallet_consumption'),

    # ============ RATINGS ============
    path('ratings/', views.my_ratings, name='my_ratings'),

    # ============ PENALTIES ============
    path('penalties/my/', views.my_penalties, name='my_penalties'),

    # ============ FESTIVAL GIFTS ============
    path('gifts/eligible/', views.eligible_festival_gifts, name='eligible_festival_gifts'),

    # ============ NOTIFICATIONS ============
    path('notifications/', views.my_notifications, name='my_notifications'),
    path('notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),

    # ============ DRIVER SPECIFIC ============
    path('driver/dashboard/', views.driver_dashboard, name='driver_dashboard'),
    path('driver/bookings/<int:booking_id>/accept/', views.driver_accept_booking, name='driver_accept_booking'),

    # ============ ADMIN VEHICLE CATEGORIES & PRICING ============
    path('admin/vehicle-categories/', views.admin_vehicle_categories, name='admin_vehicle_categories'),
    path('admin/vehicle-categories/<int:category_id>/', views.admin_vehicle_category_detail, name='admin_vehicle_category_detail'),
    path('admin/pricing-slabs/', views.admin_pricing_slabs, name='admin_pricing_slabs'),
    path('admin/pricing-slabs/<int:slab_id>/', views.admin_pricing_slab_detail, name='admin_pricing_slab_detail'),

    # ============ ADMIN PENALTIES ============
    path('admin/penalties/', views.admin_penalties, name='admin_penalties'),
    path('admin/penalties/<int:penalty_id>/', views.admin_update_penalty, name='admin_update_penalty'),

    # ============ ADMIN FESTIVAL GIFTS ============
    path('admin/festival-gifts/', views.admin_festival_gifts, name='admin_festival_gifts'),
    path('admin/festival-gifts/<int:gift_id>/deliver/', views.admin_mark_gift_delivered, name='admin_mark_gift_delivered'),

    # ============ ADMIN TRIP MONITORING ============
    path('admin/monitor/trips/', views.admin_monitor_trips, name='admin_monitor_trips'),

    # ============ ADMIN REPORTS ============
    path('admin/reports/', views.admin_reports, name='admin_reports'),

    # ============ ADMIN USER MANAGEMENT ============
    path('admin/users/', views.admin_users_list, name='admin_users_list'),
    path('admin/users/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),
    path('admin/users/<int:user_id>/block/', views.admin_block_user, name='admin_block_user'),

    # ============ ADMIN KYC ============
    path('admin/kyc/pending/', views.admin_pending_kyc, name='admin_pending_kyc'),
    path('admin/kyc/<int:doc_id>/verify/', views.admin_verify_kyc, name='admin_verify_kyc'),

    # ============ ADMIN VEHICLES ============
    path('admin/vehicles/pending/', views.admin_pending_vehicles, name='admin_pending_vehicles'),
    path('admin/vehicles/<int:vehicle_id>/verify/', views.admin_verify_vehicle, name='admin_verify_vehicle'),

    # ============ ADMIN DISPUTES ============
    path('admin/disputes/', views.admin_disputes, name='admin_disputes'),
    path('admin/disputes/<int:dispute_id>/', views.admin_update_dispute, name='admin_update_dispute'),

    # ============ ADMIN LOGS ============
    path('admin/logs/', views.admin_logs, name='admin_logs'),
]