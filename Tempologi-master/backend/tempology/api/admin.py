from django.contrib import admin
from .models import *

# Simple registration without custom admin classes
admin.site.register(User)
admin.site.register(CorporateProfile)
admin.site.register(KYCDocument)
admin.site.register(SavedAddress)
admin.site.register(Vehicle)
admin.site.register(VehiclePhoto)
admin.site.register(VehicleSchedule)
admin.site.register(Load)
admin.site.register(Bid)
admin.site.register(Booking)
admin.site.register(ShipmentTracking)
admin.site.register(Wallet)
admin.site.register(WalletTransaction)
admin.site.register(Payment)
admin.site.register(Rating)
admin.site.register(Dispute)
admin.site.register(Notification)
admin.site.register(AdminLog)