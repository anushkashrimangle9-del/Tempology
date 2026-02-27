# services/pricing_calculator.py
import math
from decimal import Decimal
from django.utils import timezone
from django.db.models import Q
from .models import *
from datetime import datetime


class PricingCalculator:
    """
    Advanced pricing calculator with slab-based logic and dynamic factors
    Implements:
    - ₹7,000 for 240 km base rate
    - 35 MT for 100 km slab
    - Per ton pricing
    - Minimum 5 km slab for part load
    - Peak/Festival pricing
    """

    @staticmethod
    def calculate_distance(lat1, lng1, lat2, lng2):
        """
        Calculate distance between two points using Haversine formula
        Returns distance in kilometers
        """
        if not all([lat1, lng1, lat2, lng2]):
            return None

        # Convert to float if Decimal
        lat1 = float(lat1)
        lng1 = float(lng1)
        lat2 = float(lat2)
        lng2 = float(lng2)

        # Radius of Earth in kilometers
        R = 6371.0

        # Convert to radians
        lat1_rad = math.radians(lat1)
        lon1_rad = math.radians(lng1)
        lat2_rad = math.radians(lat2)
        lon2_rad = math.radians(lng2)

        # Differences
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad

        # Haversine formula
        a = math.sin(dlat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = R * c

        return round(distance, 2)

    @staticmethod
    def get_applicable_slab(vehicle_category, distance_km, weight_kg):
        """
        Find applicable pricing slab based on distance and weight
        """
        weight_ton = weight_kg / 1000

        # Find matching slab
        slab = PricingSlab.objects.filter(
            vehicle_category=vehicle_category,
            is_active=True,
            min_distance__lte=distance_km
        ).filter(
            Q(max_distance__isnull=True) | Q(max_distance__gte=distance_km)
        ).filter(
            min_weight_ton__lte=weight_ton
        ).filter(
            Q(max_weight_ton__isnull=True) | Q(max_weight_ton__gte=weight_ton)
        ).order_by('min_distance', 'min_weight_ton').first()

        return slab

    @staticmethod
    def calculate_price(load, vehicle):
        """
        Calculate total price based on distance, weight, and applicable slabs
        """
        from decimal import Decimal

        # Get distance
        distance = PricingCalculator.calculate_distance(
            load.pickup_lat, load.pickup_lng,
            load.drop_lat, load.drop_lng
        )

        if not distance:
            raise ValueError("Could not calculate distance. Missing coordinates.")

        # Get vehicle category
        try:
            vehicle_category = VehicleCategory.objects.get(
                vehicle_type=vehicle.vehicle_type,
                capacity_ton=vehicle.capacity_ton,
                is_active=True
            )
        except VehicleCategory.DoesNotExist:
            # Create default category if not exists
            vehicle_category = VehicleCategory.objects.create(
                name=f"{vehicle.get_vehicle_type_display()} - {vehicle.capacity_ton} ton",
                vehicle_type=vehicle.vehicle_type,
                capacity_ton=vehicle.capacity_ton,
                length_ft=vehicle.length_ft or 0,
                base_rate_per_km=30,
                base_distance_km=240,
                base_charge=7000
            )

        # Get applicable slab
        slab = PricingCalculator.get_applicable_slab(
            vehicle_category,
            distance,
            float(load.weight_kg)
        )

        # Base price calculation
        if slab:
            if slab.slab_type == 'distance':
                base_price = distance * slab.rate_per_km
            elif slab.slab_type == 'weight':
                weight_ton = float(load.weight_kg) / 1000
                base_price = distance * slab.rate_per_ton_km * weight_ton
            else:  # combined
                weight_ton = float(load.weight_kg) / 1000
                base_price = distance * slab.rate_per_km
                if slab.rate_per_ton_km:
                    base_price += distance * slab.rate_per_ton_km * max(0, weight_ton - 1)
        else:
            # Default calculation using base rate
            base_price = (distance / float(vehicle_category.base_distance_km)) * float(vehicle_category.base_charge)

        # Check minimum distance for part load
        if distance < 5 and load.trip_mode == 'part_load':
            base_price *= float(slab.part_load_multiplier if slab else 1.5)

        # Apply base slab minimum charge
        if slab and slab.is_base_slab and float(load.weight_kg) <= slab.base_weight_kg:
            if slab.base_charge and base_price < float(slab.base_charge):
                base_price = float(slab.base_charge)

        # Check if it's peak/festival time
        now = timezone.now()
        is_peak_time = PricingCalculator.check_peak_time(now)
        is_festival = PricingCalculator.check_festival(now)

        # Apply multipliers
        if is_festival:
            multiplier = float(slab.festival_multiplier if slab else 1.2)
        elif is_peak_time:
            multiplier = float(slab.peak_multiplier if slab else 1.1)
        else:
            multiplier = 1.0

        price_after_multiplier = base_price * multiplier

        # Round to 2 decimal places
        total_price = round(price_after_multiplier, 2)

        # Calculate per ton rate for reference
        weight_ton = float(load.weight_kg) / 1000
        per_ton_rate = total_price / weight_ton if weight_ton > 0 else 0

        return {
            'distance_km': distance,
            'base_price': round(base_price, 2),
            'applicable_slab': {
                'id': slab.slab_id if slab else None,
                'min_distance': slab.min_distance if slab else None,
                'max_distance': slab.max_distance if slab else None,
                'rate_per_km': float(slab.rate_per_km) if slab else None,
                'rate_per_ton_km': float(slab.rate_per_ton_km) if slab else None,
            } if slab else None,
            'multiplier': multiplier,
            'multiplier_reason': 'Festival' if is_festival else ('Peak Time' if is_peak_time else 'Normal'),
            'total_price': total_price,
            'per_ton_rate': round(per_ton_rate, 2),
            'breakdown': {
                'distance': distance,
                'weight_tons': weight_ton,
                'base_calculation': 'Slab Based' if slab else 'Default Rate',
                'rate_applied': float(slab.rate_per_km) if slab else float(vehicle_category.base_rate_per_km),
            }
        }

    @staticmethod
    def check_peak_time(dt):
        """Check if given time is peak hours"""
        # Peak hours: 8-11 AM and 5-8 PM on weekdays
        hour = dt.hour
        weekday = dt.weekday()  # 0-6 (Monday=0, Sunday=6)

        if weekday >= 5:  # Weekend
            return False

        return (8 <= hour <= 11) or (17 <= hour <= 20)

    @staticmethod
    def check_festival(dt):
        """Check if given date is a festival"""
        # This would integrate with a festival calendar
        # For now, return False
        return False

    @staticmethod
    def calculate_delay_penalty(original_delivery_time, actual_delivery_time, base_amount):
        """
        Calculate penalty for delayed delivery
        """
        if not actual_delivery_time or actual_delivery_time <= original_delivery_time:
            return 0

        delay_minutes = (actual_delivery_time - original_delivery_time).total_seconds() / 60
        delay_hours = delay_minutes / 60

        # Penalty structure:
        # First hour: 5% of base amount
        # Subsequent hours: 2% per hour
        if delay_hours <= 1:
            penalty_percentage = 5
        else:
            penalty_percentage = 5 + (delay_hours - 1) * 2

        # Cap at 30%
        penalty_percentage = min(penalty_percentage, 30)

        penalty_amount = (penalty_percentage / 100) * float(base_amount)

        return {
            'delay_minutes': int(delay_minutes),
            'delay_hours': round(delay_hours, 2),
            'penalty_percentage': round(penalty_percentage, 2),
            'penalty_amount': round(penalty_amount, 2)
        }

    @staticmethod
    def calculate_haulting_charge(haulting_hours, base_rate_per_hour=100):
        """
        Calculate charges for haulting
        """
        if haulting_hours <= 2:  # Free for first 2 hours
            return 0

        payable_hours = haulting_hours - 2
        return payable_hours * base_rate_per_hour

    @staticmethod
    def calculate_wallet_consumption(total_amount, wallet_balance):
        """
        Calculate wallet consumption (10% per trip as per requirement)
        """
        max_consumption = total_amount * 0.10  # 10% per trip
        actual_consumption = min(max_consumption, wallet_balance)

        return {
            'total_amount': total_amount,
            'wallet_balance': wallet_balance,
            'max_allowed_consumption': round(max_consumption, 2),
            'actual_consumption': round(actual_consumption, 2),
            'remaining_wallet': round(wallet_balance - actual_consumption, 2),
            'cash_required': round(total_amount - actual_consumption, 2)
        }