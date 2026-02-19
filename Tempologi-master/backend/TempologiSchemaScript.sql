-- ==========================================================
-- TempoLogi Database Schema
-- Version: 1.0
-- Supports: Consignee, Truck Owner, Corporate, Admin Modules
-- ==========================================================

CREATE DATABASE IF NOT EXISTS tempologi_db;
USE tempologi_db;

-- ==========================================================
-- 1. USER MANAGEMENT & AUTHENTICATION
-- ==========================================================

-- Core Users Table (All roles share this)
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE,
    phone_number VARCHAR(20) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('consignee', 'truck_owner', 'transporter', 'corporate', 'admin', 'driver') NOT NULL,
    status ENUM('active', 'inactive', 'suspended', 'banned') DEFAULT 'active',
    is_verified BOOLEAN DEFAULT FALSE,
    profile_image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Corporate Profiles (Extension for Corporate Clients)
CREATE TABLE corporate_profiles (
    corporate_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    company_name VARCHAR(150) NOT NULL,
    gst_number VARCHAR(20) UNIQUE,
    contact_person VARCHAR(100),
    credit_limit DECIMAL(15, 2) DEFAULT 0.00,
    contract_start_date DATE,
    contract_end_date DATE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- KYC Documents (For Verification)
CREATE TABLE kyc_documents (
    doc_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    document_type ENUM('aadhaar', 'pan', 'gst', 'dl', 'rc', 'fitness', 'insurance') NOT NULL,
    document_number VARCHAR(50) NOT NULL,
    file_url VARCHAR(255) NOT NULL,
    expiry_date DATE,
    verification_status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    rejection_reason VARCHAR(255),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Addresses (Saved addresses for Users/Corporates)
CREATE TABLE saved_addresses (
    address_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    address_label VARCHAR(50), -- e.g., "Warehouse A", "Home"
    street_address TEXT NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(100) NOT NULL,
    postal_code VARCHAR(20) NOT NULL,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(10, 8),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ==========================================================
-- 2. VEHICLE & FLEET MANAGEMENT (Truck Owners)
-- ==========================================================

CREATE TABLE vehicles (
    vehicle_id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL, -- User ID of the Truck Owner
    vehicle_type ENUM('mini_truck', 'tempo', 'container', 'trailer', 'open_body') NOT NULL,
    manufacturer VARCHAR(100),
    registration_number VARCHAR(20) UNIQUE NOT NULL,
    registration_year YEAR,
    capacity_ton DECIMAL(10, 2) NOT NULL,
    length_ft DECIMAL(10, 2),
    is_active BOOLEAN DEFAULT TRUE,
    verification_status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Vehicle Photos (4 Sides)
CREATE TABLE vehicle_photos (
    photo_id INT AUTO_INCREMENT PRIMARY KEY,
    vehicle_id INT NOT NULL,
    photo_url VARCHAR(255) NOT NULL,
    side ENUM('front', 'back', 'left', 'right', 'interior') NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id) ON DELETE CASCADE
);

-- Empty Return Trip Schedules (Smart Matching Core)
CREATE TABLE vehicle_schedules (
    schedule_id INT AUTO_INCREMENT PRIMARY KEY,
    vehicle_id INT NOT NULL,
    start_location VARCHAR(255) NOT NULL,
    end_location VARCHAR(255) NOT NULL,
    start_lat DECIMAL(10, 8),
    start_lng DECIMAL(10, 8),
    end_lat DECIMAL(10, 8),
    end_lng DECIMAL(10, 8),
    available_from DATETIME NOT NULL,
    available_to DATETIME NOT NULL,
    available_capacity_ton DECIMAL(10, 2),
    trip_type ENUM('one_way', 'return', 'tempopool') DEFAULT 'one_way',
    status ENUM('active', 'booked', 'expired') DEFAULT 'active',
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id) ON DELETE CASCADE
);

-- ==========================================================
-- 3. LOGISTICS: LOADS, BIDDING & MATCHING
-- ==========================================================

-- Loads Posted by Consignees
CREATE TABLE loads (
    load_id INT AUTO_INCREMENT PRIMARY KEY,
    consignee_id INT NOT NULL,
    pickup_address TEXT NOT NULL,
    drop_address TEXT NOT NULL,
    pickup_lat DECIMAL(10, 8),
    pickup_lng DECIMAL(10, 8),
    drop_lat DECIMAL(10, 8),
    drop_lng DECIMAL(10, 8),
    material_type VARCHAR(100) NOT NULL, -- e.g., Electronics, Furniture
    weight_kg DECIMAL(10, 2) NOT NULL,
    required_vehicle_type VARCHAR(50),
    pickup_date DATETIME NOT NULL,
    is_fragile BOOLEAN DEFAULT FALSE,
    special_instructions TEXT,
    trip_mode ENUM('full_truck', 'tempopool') DEFAULT 'full_truck',
    booking_type ENUM('instant', 'bidding') DEFAULT 'instant',
    budget_price DECIMAL(15, 2), -- Expected price
    status ENUM('open', 'assigned', 'in_transit', 'delivered', 'cancelled') DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (consignee_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Bids on Loads (For Bidding Model)
CREATE TABLE bids (
    bid_id INT AUTO_INCREMENT PRIMARY KEY,
    load_id INT NOT NULL,
    transporter_id INT NOT NULL,
    vehicle_id INT NOT NULL,
    bid_amount DECIMAL(15, 2) NOT NULL,
    bid_message TEXT,
    bid_status ENUM('pending', 'accepted', 'rejected', 'withdrawn') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (load_id) REFERENCES loads(load_id) ON DELETE CASCADE,
    FOREIGN KEY (transporter_id) REFERENCES users(user_id),
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id)
);

-- ==========================================================
-- 4. BOOKING & EXECUTION
-- ==========================================================

-- Confirmed Bookings
CREATE TABLE bookings (
    booking_id INT AUTO_INCREMENT PRIMARY KEY,
    load_id INT NOT NULL UNIQUE, -- One active booking per load
    consignee_id INT NOT NULL,
    transporter_id INT NOT NULL,
    vehicle_id INT NOT NULL,
    driver_id INT, -- Can be same as transporter or distinct user
    
    agreed_price DECIMAL(15, 2) NOT NULL,
    tax_amount DECIMAL(10, 2) DEFAULT 0.00,
    total_amount DECIMAL(15, 2) NOT NULL,
    
    pickup_otp VARCHAR(6),
    delivery_otp VARCHAR(6),
    
    booking_status ENUM('confirmed', 'driver_assigned', 'at_pickup', 'loaded', 'in_transit', 'at_delivery', 'completed', 'cancelled') DEFAULT 'confirmed',
    
    -- E-Docs
    eway_bill_no VARCHAR(50),
    invoice_url VARCHAR(255),
    bilty_url VARCHAR(255),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    
    FOREIGN KEY (load_id) REFERENCES loads(load_id),
    FOREIGN KEY (consignee_id) REFERENCES users(user_id),
    FOREIGN KEY (transporter_id) REFERENCES users(user_id),
    FOREIGN KEY (vehicle_id) REFERENCES vehicles(vehicle_id)
);

-- Live Tracking Logs
CREATE TABLE shipment_tracking (
    tracking_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(10, 8) NOT NULL,
    current_location_text VARCHAR(255),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id) ON DELETE CASCADE
);

-- ==========================================================
-- 5. FINANCIALS: WALLETS & ESCROW
-- ==========================================================

-- User Wallets
CREATE TABLE wallets (
    wallet_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE NOT NULL,
    balance DECIMAL(15, 2) DEFAULT 0.00,
    currency VARCHAR(3) DEFAULT 'INR',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Wallet Transactions (History)
CREATE TABLE wallet_transactions (
    transaction_id INT AUTO_INCREMENT PRIMARY KEY,
    wallet_id INT NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    transaction_type ENUM('credit', 'debit') NOT NULL,
    reference_type ENUM('booking_payment', 'refund', 'withdrawal', 'deposit', 'penalty') NOT NULL,
    reference_id INT, -- Can be booking_id
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (wallet_id) REFERENCES wallets(wallet_id)
);

-- Payments & Escrow Logic
CREATE TABLE payments (
    payment_id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    payer_id INT NOT NULL,
    payee_id INT NOT NULL, -- Truck owner
    amount DECIMAL(15, 2) NOT NULL,
    
    payment_gateway ENUM('razorpay', 'paytm', 'cashfree', 'cod', 'wallet') NOT NULL,
    gateway_txn_id VARCHAR(100),
    
    -- Escrow Statuses
    payment_status ENUM('pending', 'escrow_held', 'released_to_vendor', 'refunded', 'failed') DEFAULT 'pending',
    
    admin_commission DECIMAL(10, 2) DEFAULT 0.00, -- Platform fee
    vendor_payout DECIMAL(15, 2) DEFAULT 0.00, -- Amount to owner
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP NULL, -- When escrow is released
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id)
);

-- ==========================================================
-- 6. REPUTATION, SUPPORT & ADMIN
-- ==========================================================

-- Ratings & Reviews
CREATE TABLE ratings (
    rating_id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    reviewer_id INT NOT NULL, -- Who is giving rating
    reviewee_id INT NOT NULL, -- Who is receiving rating
    score INT CHECK (score BETWEEN 1 AND 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id)
);

-- Disputes
CREATE TABLE disputes (
    dispute_id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    raised_by INT NOT NULL,
    reason_category ENUM('damaged_goods', 'late_delivery', 'payment_issue', 'vehicle_condition', 'other') NOT NULL,
    description TEXT,
    evidence_url VARCHAR(255), -- Photo proof
    status ENUM('open', 'investigating', 'resolved', 'closed') DEFAULT 'open',
    admin_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(booking_id),
    FOREIGN KEY (raised_by) REFERENCES users(user_id)
);

-- Admin Logs (Audit Trail)
CREATE TABLE admin_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL, -- e.g., "KYC_APPROVAL"
    target_id INT, -- User ID or Booking ID affected
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_user_id) REFERENCES users(user_id)
);

-- Notifications
CREATE TABLE notifications (
    notification_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(100),
    message TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    type ENUM('booking', 'payment', 'system', 'promo') DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Indexes for Performance
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_phone ON users(phone_number);
CREATE INDEX idx_vehicle_owner ON vehicles(owner_id);
CREATE INDEX idx_load_location ON loads(pickup_lat, pickup_lng);
CREATE INDEX idx_schedule_location ON vehicle_schedules(start_lat, start_lng);
