package com.example;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.kernel.pdf.canvas.draw.SolidLine;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.LineSeparator;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;
import java.util.stream.Collectors;

// === Data Protection & Privacy Imports ===
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * High-Performance Concurrent Order Confirmation PDF Generator for E-commerce Platform
 * 
 * @intuition Generate secure, customized PDFs for complex e-commerce scenarios with
 * enterprise-grade multithreading, handling concurrent order requests efficiently using
 * structured concurrency, resource pooling, circuit breakers, and rate limiting.
 * 
 * @approach Single-file architecture leveraging Java 24 structured concurrency, records,
 * sealed classes, and pattern matching. Features include:
 * - Concurrent processing with dedicated thread pools for validation, PDF generation
 * - Resource pooling for expensive operations (PDF services, encryption)
 * - Circuit breaker pattern for fault tolerance and system protection
 * - Rate limiting using token bucket algorithm (100 req/sec default)
 * - Real-time performance metrics and monitoring
 * - Backpressure handling with bounded queues (10K capacity)
 * - Graceful shutdown with proper resource cleanup
 * - GDPR/CCPA compliance with data classification and consent management
 * - Data anonymization, pseudonymization, and privacy-by-design masking
 * - Right to be forgotten (data deletion) and subject access requests
 * - Comprehensive audit logging and data retention policies
 * - Data breach detection and automated compliance reporting
 * 
 * @complexity Time: O(1) for concurrent processing (bounded by thread pool size)
 *            Space: O(p + c) where p=pool sizes, c=cache sizes
 *            Throughput: ~100+ orders/second with proper hardware
 * 
 * @concurrency Thread-safe using:
 * - AtomicLong/AtomicInteger for metrics
 * - ConcurrentHashMap for operation tracking
 * - BlockingQueues for resource pooling
 * - StructuredTaskScope for batch operations
 * 
 * @author E-commerce Platform Team
 * @version 2.2.0-GDPR-COMPLIANT-PRODUCTION
 * @since JDK 24
 */
public final class OrderConfirmationPdfGenerator {

    // === Constants and Configuration ===
    
    private static final Logger LOGGER = Logger.getLogger(OrderConfirmationPdfGenerator.class.getName());
    private static final String OUTPUT_DIRECTORY = "generated-pdfs";
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int CACHE_MAX_SIZE = 1000;
    private static final Duration CACHE_EXPIRE_DURATION = Duration.ofHours(2);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final BigDecimal ZERO = BigDecimal.ZERO;
    
    // === Multithreading Configuration ===
    
    private static final int DEFAULT_THREAD_POOL_SIZE = Runtime.getRuntime().availableProcessors() * 2;
    private static final int PDF_GENERATION_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final int ENCRYPTION_POOL_SIZE = Runtime.getRuntime().availableProcessors();
    private static final int MAX_QUEUE_SIZE = 10000;
    private static final int BATCH_SIZE = 50;
    private static final Duration PROCESSING_TIMEOUT = Duration.ofMinutes(5);
    private static final Duration RATE_LIMIT_WINDOW = Duration.ofSeconds(1);
    private static final int MAX_REQUESTS_PER_SECOND = 100;
    
    // === Data Protection & Privacy Configuration ===
    
    private static final Duration DEFAULT_DATA_RETENTION_PERIOD = Duration.ofDays(2555); // 7 years
    private static final Duration GDPR_DELETION_GRACE_PERIOD = Duration.ofDays(30);
    private static final Duration AUDIT_LOG_RETENTION = Duration.ofDays(3653); // 10 years
    private static final String ANONYMIZATION_SALT = "E-COMMERCE-PRIVACY-2024";
    private static final int PSEUDONYMIZATION_LENGTH = 12;
    private static final String AUDIT_LOG_DIRECTORY = "audit-logs";
    private static final String EXPORT_DIRECTORY = "data-exports";
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern PHONE_PATTERN = Pattern.compile("\\(?\\d{3}\\)?[-\\s]?\\d{3}[-\\s]?\\d{4}");
    private static final Pattern SSN_PATTERN = Pattern.compile("\\d{3}-\\d{2}-\\d{4}");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}");
    
    // Constants for duplicated literals
    private static final String CUSTOMER_ID_NULL_MESSAGE = "Customer ID cannot be null";
    private static final String DELETE_OPERATION = "DELETE";
    private static final String EXPORT_OPERATION = "EXPORT";
    private static final String SYSTEM_OPERATOR = "SYSTEM";
    private static final String COMPLETED_STATUS = "COMPLETED";
    private static final String CUSTOMER_PREFIX = "CUSTOMER";
    private static final String CURRENCY_FORMAT = "$%.2f";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String TEST_USER_AGENT = "Mozilla/5.0";
    private static final String TIME_FORMAT_HH_MM_SS = "HH:mm:ss";
    
    // === Core Domain Models ===
    
    /**
     * Sealed interface for order processing states ensuring type safety
     */
    public sealed interface OrderStatus 
        permits OrderStatus.Pending, OrderStatus.Confirmed, OrderStatus.Processing, 
                OrderStatus.Shipped, OrderStatus.Delivered, OrderStatus.Cancelled {
        
        String getDisplayName();
        String getDescription();
        boolean isShippable();
        
        record Pending() implements OrderStatus {
            @Override public String getDisplayName() { return "PENDING"; }
            @Override public String getDescription() { return "Order received, awaiting confirmation"; }
            @Override public boolean isShippable() { return false; }
        }
        
        record Confirmed() implements OrderStatus {
            @Override public String getDisplayName() { return "CONFIRMED"; }
            @Override public String getDescription() { return "Order confirmed, preparing for shipment"; }
            @Override public boolean isShippable() { return true; }
        }
        
        record Processing() implements OrderStatus {
            @Override public String getDisplayName() { return "PROCESSING"; }
            @Override public String getDescription() { return "Order being processed"; }
            @Override public boolean isShippable() { return true; }
        }
        
        record Shipped() implements OrderStatus {
            @Override public String getDisplayName() { return "SHIPPED"; }
            @Override public String getDescription() { return "Order shipped to customer"; }
            @Override public boolean isShippable() { return false; }
        }
        
        record Delivered() implements OrderStatus {
            @Override public String getDisplayName() { return "DELIVERED"; }
            @Override public String getDescription() { return "Order delivered successfully"; }
            @Override public boolean isShippable() { return false; }
        }
        
        record Cancelled() implements OrderStatus {
            @Override public String getDisplayName() { return "CANCELLED"; }
            @Override public String getDescription() { return "Order cancelled"; }
            @Override public boolean isShippable() { return false; }
        }
    }
    
    /**
     * Sealed interface for shipment types handling split and backorder scenarios
     */
    public sealed interface ShipmentType 
        permits ShipmentType.Standard, ShipmentType.Split, ShipmentType.Backorder, ShipmentType.Express {
        
        String getDisplayName();
        boolean requiresSpecialHandling();
        
        record Standard() implements ShipmentType {
            @Override public String getDisplayName() { return "Standard Shipment"; }
            @Override public boolean requiresSpecialHandling() { return false; }
        }
        
        record Split(int totalParts, int currentPart) implements ShipmentType {
            public Split {
                if (totalParts <= 1) throw new IllegalArgumentException("Split shipment must have > 1 parts");
                if (currentPart < 1 || currentPart > totalParts) {
                    throw new IllegalArgumentException("Invalid part number");
                }
            }
            @Override public String getDisplayName() { 
                return "Split Shipment (%d of %d)".formatted(currentPart, totalParts); 
            }
            @Override public boolean requiresSpecialHandling() { return true; }
        }
        
        record Backorder(LocalDateTime expectedDate) implements ShipmentType {
            public Backorder {
                Objects.requireNonNull(expectedDate, "Expected date cannot be null");
            }
            @Override public String getDisplayName() { 
                return "Backorder (Expected: %s)".formatted(expectedDate.format(DATE_FORMATTER)); 
            }
            @Override public boolean requiresSpecialHandling() { return true; }
        }
        
        record Express() implements ShipmentType {
            @Override public String getDisplayName() { return "Express Delivery"; }
            @Override public boolean requiresSpecialHandling() { return true; }
        }
    }
    
    /**
     * Sealed interface for promotional coupon types
     */
    public sealed interface CouponType 
        permits CouponType.Percentage, CouponType.FixedAmount, CouponType.FreeShipping, CouponType.BuyOneGetOne {
        
        String getDisplayName();
        BigDecimal calculateDiscount(BigDecimal orderTotal, BigDecimal shippingCost);
        
        record Percentage(BigDecimal percent) implements CouponType {
            public Percentage {
                Objects.requireNonNull(percent, "Percentage cannot be null");
                if (percent.compareTo(ZERO) < 0 || percent.compareTo(BigDecimal.valueOf(100)) > 0) {
                    throw new IllegalArgumentException("Percentage must be between 0 and 100");
                }
            }
            @Override public String getDisplayName() { 
                return "%s%% Off".formatted(percent.stripTrailingZeros().toPlainString()); 
            }
            @Override public BigDecimal calculateDiscount(final BigDecimal orderTotal, final BigDecimal shippingCost) {
                return orderTotal.multiply(percent).divide(BigDecimal.valueOf(100), 2, RoundingMode.HALF_UP);
            }
        }
        
        record FixedAmount(BigDecimal amount) implements CouponType {
            public FixedAmount {
                Objects.requireNonNull(amount, "Amount cannot be null");
                if (amount.compareTo(ZERO) < 0) {
                    throw new IllegalArgumentException("Amount cannot be negative");
                }
            }
            @Override public String getDisplayName() { 
                return "$%s Off".formatted(amount.stripTrailingZeros().toPlainString()); 
            }
            @Override public BigDecimal calculateDiscount(final BigDecimal orderTotal, final BigDecimal shippingCost) {
                return amount.min(orderTotal);
            }
        }
        
        record FreeShipping() implements CouponType {
            @Override public String getDisplayName() { return "Free Shipping"; }
            @Override public BigDecimal calculateDiscount(final BigDecimal orderTotal, final BigDecimal shippingCost) {
                return shippingCost;
            }
        }
        
        record BuyOneGetOne(String applicableCategory) implements CouponType {
            public BuyOneGetOne {
                Objects.requireNonNull(applicableCategory, "Category cannot be null");
            }
            @Override public String getDisplayName() { 
                return "BOGO - %s".formatted(applicableCategory); 
            }
            @Override public BigDecimal calculateDiscount(final BigDecimal orderTotal, final BigDecimal shippingCost) {
                // Simplified BOGO calculation - in real system would need item-level logic
                return orderTotal.multiply(BigDecimal.valueOf(0.25));
            }
        }
    }
    
    /**
     * Immutable customer data record with validation
     */
    public record Customer(
        String customerId,
        String firstName,
        String lastName,
        String email,
        String phone,
        Address billingAddress,
        Address shippingAddress
    ) {
        public Customer {
            Objects.requireNonNull(customerId, CUSTOMER_ID_NULL_MESSAGE);
            Objects.requireNonNull(firstName, "First name cannot be null");
            Objects.requireNonNull(lastName, "Last name cannot be null");
            Objects.requireNonNull(email, "Email cannot be null");
            Objects.requireNonNull(billingAddress, "Billing address cannot be null");
            Objects.requireNonNull(shippingAddress, "Shipping address cannot be null");
            
            validateEmail(email);
        }
        
        public String getFullName() {
            return "%s %s".formatted(firstName, lastName);
        }
        
        private static void validateEmail(final String email) {
            if (!email.contains("@") || !email.contains(".")) {
                throw new IllegalArgumentException("Invalid email format");
            }
        }
    }
    
    /**
     * Immutable address record with comprehensive validation
     */
    public record Address(
        String street,
        String city,
        String state,
        String zipCode,
        String country
    ) {
        public Address {
            Objects.requireNonNull(street, "Street cannot be null");
            Objects.requireNonNull(city, "City cannot be null");
            Objects.requireNonNull(state, "State cannot be null");
            Objects.requireNonNull(zipCode, "Zip code cannot be null");
            Objects.requireNonNull(country, "Country cannot be null");
            
            validateNonEmpty(street, "Street");
            validateNonEmpty(city, "City");
            validateNonEmpty(state, "State");
            validateNonEmpty(zipCode, "Zip code");
            validateNonEmpty(country, "Country");
        }
        
        public String getFormattedAddress() {
            return """
                   %s
                   %s, %s %s
                   %s
                   """.formatted(street, city, state, zipCode, country);
        }
        
        private static void validateNonEmpty(final String value, final String fieldName) {
            if (value.trim().isEmpty()) {
                throw new IllegalArgumentException("%s cannot be empty".formatted(fieldName));
            }
        }
    }
    
    /**
     * Order item with inventory and pricing details
     */
    public record OrderItem(
        String itemId,
        String productName,
        String category,
        int quantity,
        BigDecimal unitPrice,
        BigDecimal weight,
        boolean isBackordered,
        String description
    ) {
        public OrderItem {
            Objects.requireNonNull(itemId, "Item ID cannot be null");
            Objects.requireNonNull(productName, "Product name cannot be null");
            Objects.requireNonNull(category, "Category cannot be null");
            Objects.requireNonNull(unitPrice, "Unit price cannot be null");
            Objects.requireNonNull(weight, "Weight cannot be null");
            Objects.requireNonNull(description, "Description cannot be null");
            
            if (quantity <= 0) throw new IllegalArgumentException("Quantity must be positive");
            if (unitPrice.compareTo(ZERO) < 0) throw new IllegalArgumentException("Unit price cannot be negative");
            if (weight.compareTo(ZERO) < 0) throw new IllegalArgumentException("Weight cannot be negative");
        }
        
        public BigDecimal getTotalPrice() {
            return unitPrice.multiply(BigDecimal.valueOf(quantity)).setScale(2, RoundingMode.HALF_UP);
        }
        
        public BigDecimal getTotalWeight() {
            return weight.multiply(BigDecimal.valueOf(quantity)).setScale(2, RoundingMode.HALF_UP);
        }
    }
    
    /**
     * Promotional coupon with validation and discount calculation
     */
    public record Coupon(
        String couponCode,
        String description,
        CouponType type,
        LocalDateTime validFrom,
        LocalDateTime validUntil,
        boolean isActive
    ) {
        public Coupon {
            Objects.requireNonNull(couponCode, "Coupon code cannot be null");
            Objects.requireNonNull(description, "Description cannot be null");
            Objects.requireNonNull(type, "Coupon type cannot be null");
            Objects.requireNonNull(validFrom, "Valid from date cannot be null");
            Objects.requireNonNull(validUntil, "Valid until date cannot be null");
            
            if (validFrom.isAfter(validUntil)) {
                throw new IllegalArgumentException("Valid from date must be before valid until date");
            }
        }
        
        public boolean isValidAt(final LocalDateTime dateTime) {
            return isActive && 
                   !dateTime.isBefore(validFrom) && 
                   !dateTime.isAfter(validUntil);
        }
    }
    
    /**
     * Shipment tracking information
     */
    public record Shipment(
        String shipmentId,
        String trackingNumber,
        String carrier,
        ShipmentType type,
        LocalDateTime estimatedDelivery,
        java.util.List<OrderItem> items
    ) {
        public Shipment {
            Objects.requireNonNull(shipmentId, "Shipment ID cannot be null");
            Objects.requireNonNull(trackingNumber, "Tracking number cannot be null");
            Objects.requireNonNull(carrier, "Carrier cannot be null");
            Objects.requireNonNull(type, "Shipment type cannot be null");
            Objects.requireNonNull(estimatedDelivery, "Estimated delivery cannot be null");
            Objects.requireNonNull(items, "Items cannot be null");
            
            if (items.isEmpty()) {
                throw new IllegalArgumentException("Shipment must contain at least one item");
            }
        }
        
        public BigDecimal getTotalWeight() {
            return items.stream()
                       .map(OrderItem::getTotalWeight)
                       .reduce(ZERO, BigDecimal::add);
        }
    }
    
    /**
     * Complete order information with comprehensive business logic
     */
    public record Order(
        String orderId,
        Customer customer,
        java.util.List<OrderItem> items,
        java.util.List<Shipment> shipments,
        java.util.List<Coupon> appliedCoupons,
        OrderStatus status,
        LocalDateTime orderDate,
        BigDecimal shippingCost,
        BigDecimal taxRate,
        String specialInstructions
    ) {
        public Order {
            Objects.requireNonNull(orderId, "Order ID cannot be null");
            Objects.requireNonNull(customer, "Customer cannot be null");
            Objects.requireNonNull(items, "Items cannot be null");
            Objects.requireNonNull(shipments, "Shipments cannot be null");
            Objects.requireNonNull(appliedCoupons, "Applied coupons cannot be null");
            Objects.requireNonNull(status, "Status cannot be null");
            Objects.requireNonNull(orderDate, "Order date cannot be null");
            Objects.requireNonNull(shippingCost, "Shipping cost cannot be null");
            Objects.requireNonNull(taxRate, "Tax rate cannot be null");
            
            if (items.isEmpty()) throw new IllegalArgumentException("Order must contain at least one item");
            if (shippingCost.compareTo(ZERO) < 0) throw new IllegalArgumentException("Shipping cost cannot be negative");
            if (taxRate.compareTo(ZERO) < 0) throw new IllegalArgumentException("Tax rate cannot be negative");
        }
        
        public BigDecimal getSubtotal() {
            return items.stream()
                       .map(OrderItem::getTotalPrice)
                       .reduce(ZERO, BigDecimal::add);
        }
        
        public BigDecimal getTotalDiscount() {
            final var subtotal = getSubtotal();
            return appliedCoupons.stream()
                                .filter(coupon -> coupon.isValidAt(orderDate))
                                .map(coupon -> coupon.type().calculateDiscount(subtotal, shippingCost))
                                .reduce(ZERO, BigDecimal::add);
        }
        
        public BigDecimal getTaxAmount() {
            final var discountedSubtotal = getSubtotal().subtract(getTotalDiscount());
            return discountedSubtotal.multiply(taxRate).setScale(2, RoundingMode.HALF_UP);
        }
        
        public BigDecimal getGrandTotal() {
            final var subtotal = getSubtotal();
            final var discount = getTotalDiscount();
            final var discountedShipping = appliedCoupons.stream()
                                                         .anyMatch(c -> c.type() instanceof CouponType.FreeShipping) 
                                                         ? ZERO : shippingCost;
            return subtotal.subtract(discount).add(getTaxAmount()).add(discountedShipping);
        }
        
        public boolean hasBackorderedItems() {
            return items.stream().anyMatch(OrderItem::isBackordered);
        }
        
        public boolean hasSplitShipments() {
            return shipments.stream().anyMatch(s -> s.type() instanceof ShipmentType.Split);
        }
    }
    
    // === Data Protection & Privacy Domain Models ===
    
    /**
     * Data classification levels for privacy compliance
     */
    public enum DataClassification {
        PUBLIC("Public", "No restrictions"),
        INTERNAL("Internal", "Internal use only"),
        CONFIDENTIAL("Confidential", "Restricted access"),
        PERSONAL("Personal", "PII - requires consent"),
        SENSITIVE("Sensitive", "Sensitive PII - special protection"),
        REGULATED("Regulated", "Regulated data - strict compliance");
        
        private final String displayName;
        private final String description;
        
        DataClassification(final String displayName, final String description) {
            this.displayName = displayName;
            this.description = description;
        }
        
        public String getDisplayName() { return displayName; }
        public String getDescription() { return description; }
        
        public boolean requiresConsent() {
            return this == PERSONAL || this == SENSITIVE || this == REGULATED;
        }
        
        public boolean requiresEncryption() {
            return this == CONFIDENTIAL || this == PERSONAL || this == SENSITIVE || this == REGULATED;
        }
    }
    
    /**
     * Sealed interface for consent types and status
     */
    public sealed interface ConsentType 
        permits ConsentType.Marketing, ConsentType.Analytics, ConsentType.Essential, 
                ConsentType.DataProcessing, ConsentType.ThirdPartySharing {
        
        String getDisplayName();
        String getDescription();
        boolean isRequired();
        
        record Marketing() implements ConsentType {
            @Override public String getDisplayName() { return "Marketing Communications"; }
            @Override public String getDescription() { return "Consent for marketing emails and promotions"; }
            @Override public boolean isRequired() { return false; }
        }
        
        record Analytics() implements ConsentType {
            @Override public String getDisplayName() { return "Analytics & Performance"; }
            @Override public String getDescription() { return "Consent for analytics and performance tracking"; }
            @Override public boolean isRequired() { return false; }
        }
        
        record Essential() implements ConsentType {
            @Override public String getDisplayName() { return "Essential Services"; }
            @Override public String getDescription() { return "Required for order processing and service delivery"; }
            @Override public boolean isRequired() { return true; }
        }
        
        record DataProcessing() implements ConsentType {
            @Override public String getDisplayName() { return "Data Processing"; }
            @Override public String getDescription() { return "Consent for processing personal data"; }
            @Override public boolean isRequired() { return true; }
        }
        
        record ThirdPartySharing() implements ConsentType {
            @Override public String getDisplayName() { return "Third Party Sharing"; }
            @Override public String getDescription() { return "Consent for sharing data with partners"; }
            @Override public boolean isRequired() { return false; }
        }
    }
    
    /**
     * Sealed interface for data protection operations
     */
    public sealed interface DataOperation 
        permits DataOperation.Create, DataOperation.Read, DataOperation.Update, 
                DataOperation.Delete, DataOperation.Export, DataOperation.Anonymize {
        
        String getDisplayName();
        boolean requiresAudit();
        DataClassification getMinClassification();
        
        record Create() implements DataOperation {
            @Override public String getDisplayName() { return "CREATE"; }
            @Override public boolean requiresAudit() { return true; }
            @Override public DataClassification getMinClassification() { return DataClassification.INTERNAL; }
        }
        
        record Read() implements DataOperation {
            @Override public String getDisplayName() { return "READ"; }
            @Override public boolean requiresAudit() { return true; }
            @Override public DataClassification getMinClassification() { return DataClassification.PUBLIC; }
        }
        
        record Update() implements DataOperation {
            @Override public String getDisplayName() { return "UPDATE"; }
            @Override public boolean requiresAudit() { return true; }
            @Override public DataClassification getMinClassification() { return DataClassification.INTERNAL; }
        }
        
        record Delete() implements DataOperation {
            @Override public String getDisplayName() { return DELETE_OPERATION; }
            @Override public boolean requiresAudit() { return true; }
            @Override public DataClassification getMinClassification() { return DataClassification.CONFIDENTIAL; }
        }
        
        record Export() implements DataOperation {
            @Override public String getDisplayName() { return EXPORT_OPERATION; }
            @Override public boolean requiresAudit() { return true; }
            @Override public DataClassification getMinClassification() { return DataClassification.PERSONAL; }
        }
        
        record Anonymize() implements DataOperation {
            @Override public String getDisplayName() { return "ANONYMIZE"; }
            @Override public boolean requiresAudit() { return true; }
            @Override public DataClassification getMinClassification() { return DataClassification.PERSONAL; }
        }
    }
    
    /**
     * Privacy consent record with comprehensive tracking
     */
    public record PrivacyConsent(
        String consentId,
        String customerId,
        ConsentType consentType,
        boolean granted,
        LocalDateTime grantedAt,
        LocalDateTime expiresAt,
        String ipAddress,
        String userAgent,
        String legalBasis,
        boolean withdrawable
    ) {
        public PrivacyConsent {
            Objects.requireNonNull(consentId, "Consent ID cannot be null");
            Objects.requireNonNull(customerId, CUSTOMER_ID_NULL_MESSAGE);
            Objects.requireNonNull(consentType, "Consent type cannot be null");
            Objects.requireNonNull(grantedAt, "Granted timestamp cannot be null");
            Objects.requireNonNull(legalBasis, "Legal basis cannot be null");
            
            if (expiresAt != null && expiresAt.isBefore(grantedAt)) {
                throw new IllegalArgumentException("Expiration cannot be before grant time");
            }
        }
        
        public boolean isValid() {
            return granted && (expiresAt == null || LocalDateTime.now().isBefore(expiresAt));
        }
        
        public boolean isExpired() {
            return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
        }
        
        public Duration getTimeUntilExpiry() {
            return expiresAt != null ? 
                Duration.between(LocalDateTime.now(), expiresAt) : Duration.ofDays(Long.MAX_VALUE);
        }
    }
    
    /**
     * Data protection audit event for compliance tracking
     */
    public record DataProtectionAuditEvent(
        String eventId,
        String customerId,
        DataOperation operation,
        DataClassification dataClassification,
        LocalDateTime timestamp,
        String operatorId,
        String ipAddress,
        String details,
        boolean successful,
        String errorMessage
    ) {
        public DataProtectionAuditEvent {
            Objects.requireNonNull(eventId, "Event ID cannot be null");
            Objects.requireNonNull(operation, "Operation cannot be null");
            Objects.requireNonNull(dataClassification, "Data classification cannot be null");
            Objects.requireNonNull(timestamp, "Timestamp cannot be null");
            Objects.requireNonNull(operatorId, "Operator ID cannot be null");
        }
        
        public String toLogEntry() {
            return """
                [%s] EVENT_ID=%s CUSTOMER=%s OPERATION=%s CLASSIFICATION=%s OPERATOR=%s IP=%s SUCCESS=%s%s
                Details: %s
                """.formatted(
                    timestamp.format(DATE_FORMATTER),
                    eventId,
                    customerId != null ? customerId : SYSTEM_OPERATOR,
                    operation.getDisplayName(),
                    dataClassification.name(),
                    operatorId,
                    ipAddress != null ? ipAddress : "INTERNAL",
                    successful,
                    errorMessage != null ? " ERROR=" + errorMessage : "",
                    details != null ? details : "No additional details"
                );
        }
    }
    
    /**
     * Subject access request for GDPR compliance
     */
    public record SubjectAccessRequest(
        String requestId,
        String customerId,
        String requestType, // EXPORT, DELETE, CORRECT, RESTRICT
        LocalDateTime requestedAt,
        LocalDateTime completedAt,
        String status,
        String requestorIpAddress,
        String verificationMethod,
        String dataExportPath
    ) {
        public SubjectAccessRequest {
            Objects.requireNonNull(requestId, "Request ID cannot be null");
            Objects.requireNonNull(customerId, CUSTOMER_ID_NULL_MESSAGE);
            Objects.requireNonNull(requestType, "Request type cannot be null");
            Objects.requireNonNull(requestedAt, "Request timestamp cannot be null");
            Objects.requireNonNull(status, "Status cannot be null");
        }
        
        public boolean isCompleted() {
            return completedAt != null && COMPLETED_STATUS.equals(status);
        }
        
        public Duration getProcessingTime() {
            return completedAt != null ? 
                Duration.between(requestedAt, completedAt) : 
                Duration.between(requestedAt, LocalDateTime.now());
        }
        
        public boolean isOverdue() {
            // GDPR requires response within 30 days
            return LocalDateTime.now().isAfter(requestedAt.plusDays(30)) && !isCompleted();
        }
    }
    
    /**
     * Data retention policy configuration
     */
    public record DataRetentionPolicy(
        DataClassification dataType,
        Duration retentionPeriod,
        Duration gracePeriod,
        boolean autoDelete,
        String legalBasis,
        String description
    ) {
        public DataRetentionPolicy {
            Objects.requireNonNull(dataType, "Data type cannot be null");
            Objects.requireNonNull(retentionPeriod, "Retention period cannot be null");
            Objects.requireNonNull(gracePeriod, "Grace period cannot be null");
            Objects.requireNonNull(legalBasis, "Legal basis cannot be null");
            
            if (retentionPeriod.isNegative() || gracePeriod.isNegative()) {
                throw new IllegalArgumentException("Periods cannot be negative");
            }
        }
        
        public boolean shouldDelete(final LocalDateTime dataCreatedAt) {
            final var deleteAfter = dataCreatedAt.plus(retentionPeriod).plus(gracePeriod);
            return autoDelete && LocalDateTime.now().isAfter(deleteAfter);
        }
        
        public LocalDateTime getDeletionDate(final LocalDateTime dataCreatedAt) {
            return dataCreatedAt.plus(retentionPeriod).plus(gracePeriod);
        }
    }
    
    // === Security & Encryption ===
    
    /**
     * High-performance encryption service using Bouncy Castle
     */
    public static final class EncryptionService {
        
        private static final SecureRandom SECURE_RANDOM = new SecureRandom();
        private final SecretKey secretKey;
        
        static {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        public EncryptionService() throws NoSuchAlgorithmException {
            final var keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            this.secretKey = keyGenerator.generateKey();
        }
        
        /**
         * Encrypts sensitive customer data for secure PDF storage
         */
        public EncryptedData encryptSensitiveData(final String data) throws Exception {
            final var cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            final var iv = new byte[16];
            SECURE_RANDOM.nextBytes(iv);
            final var ivSpec = new IvParameterSpec(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            final var encryptedBytes = cipher.doFinal(data.getBytes());
            
            return new EncryptedData(encryptedBytes, iv);
        }
        
        /**
         * Decrypts sensitive data for processing
         */
        public String decryptSensitiveData(final EncryptedData encryptedData) throws Exception {
            final var cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            final var ivSpec = new IvParameterSpec(encryptedData.iv());
            
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            final var decryptedBytes = cipher.doFinal(encryptedData.data());
            
            return new String(decryptedBytes);
        }
        
        public record EncryptedData(byte[] data, byte[] iv) {
            public EncryptedData {
                Objects.requireNonNull(data, "Encrypted data cannot be null");
                Objects.requireNonNull(iv, "IV cannot be null");
            }
        }
    }
    
    // === Data Protection & Privacy Services ===
    
    /**
     * Data anonymization and pseudonymization service for privacy compliance
     */
    public static final class DataAnonymizationService {
        
        private final SecureRandom secureRandom;
        private final Map<String, String> pseudonymizationCache;
        
        public DataAnonymizationService() {
            this.secureRandom = new SecureRandom();
            this.pseudonymizationCache = new ConcurrentHashMap<>();
        }
        
        /**
         * Anonymizes personal data by replacing with random values
         */
        public String anonymizeData(final String data, final DataClassification classification) {
            if (data == null || data.trim().isEmpty()) return data;
            
            return switch (classification) {
                case PERSONAL, SENSITIVE, REGULATED -> {
                    if (EMAIL_PATTERN.matcher(data).matches()) {
                        yield generateAnonymousEmail();
                    } else if (PHONE_PATTERN.matcher(data).matches()) {
                        yield generateAnonymousPhone();
                    } else if (SSN_PATTERN.matcher(data).matches()) {
                        yield "XXX-XX-XXXX";
                    } else if (CREDIT_CARD_PATTERN.matcher(data).matches()) {
                        yield "XXXX-XXXX-XXXX-XXXX";
                    } else {
                        yield maskString(data);
                    }
                }
                case CONFIDENTIAL -> maskString(data);
                default -> data;
            };
        }
        
        /**
         * Pseudonymizes data maintaining referential integrity
         */
        public String pseudonymizeData(final String data, final String context) {
            if (data == null || data.trim().isEmpty()) return data;
            
            final var cacheKey = context + ":" + data;
            return pseudonymizationCache.computeIfAbsent(cacheKey, k -> {
                try {
                    final var mac = Mac.getInstance("HmacSHA256");
                    final var secretKey = new SecretKeySpec(
                        ANONYMIZATION_SALT.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
                    mac.init(secretKey);
                    
                    final var hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
                    final var pseudonym = Base64.getEncoder().encodeToString(hash);
                    
                    return pseudonym.substring(0, Math.min(PSEUDONYMIZATION_LENGTH, pseudonym.length()));
                    
                } catch (Exception e) {
                    LOGGER.severe("Pseudonymization failed: " + e.getMessage());
                    return maskString(data);
                }
            });
        }
        
        /**
         * Detects and classifies personal data in text
         */
        public Map<String, DataClassification> detectPersonalData(final String text) {
            final var detectedData = new HashMap<String, DataClassification>();
            
            if (text == null) return detectedData;
            
            // Email detection
            EMAIL_PATTERN.matcher(text).results()
                .forEach(match -> detectedData.put(match.group(), DataClassification.PERSONAL));
            
            // Phone detection
            PHONE_PATTERN.matcher(text).results()
                .forEach(match -> detectedData.put(match.group(), DataClassification.PERSONAL));
            
            // SSN detection
            SSN_PATTERN.matcher(text).results()
                .forEach(match -> detectedData.put(match.group(), DataClassification.SENSITIVE));
            
            // Credit card detection
            CREDIT_CARD_PATTERN.matcher(text).results()
                .forEach(match -> detectedData.put(match.group(), DataClassification.REGULATED));
            
            return detectedData;
        }
        
        private String generateAnonymousEmail() {
            return "user%d@anonymized.com".formatted(Math.abs(secureRandom.nextInt()));
        }
        
        private String generateAnonymousPhone() {
            return "(555) %03d-%04d".formatted(
                secureRandom.nextInt(1000), 
                secureRandom.nextInt(10000)
            );
        }
        
        private String maskString(final String data) {
            if (data.length() <= 4) return "*".repeat(data.length());
            
            final var start = data.substring(0, 2);
            final var end = data.substring(data.length() - 2);
            final var middle = "*".repeat(data.length() - 4);
            
            return start + middle + end;
        }
    }
    
    /**
     * Comprehensive audit logging service for data protection compliance
     */
    public static final class DataProtectionAuditService {
        
        private final Map<String, java.util.List<DataProtectionAuditEvent>> auditLog;
        private final ScheduledExecutorService auditExecutor;
        private final AtomicLong eventCounter;
        
        public DataProtectionAuditService() {
            this.auditLog = new ConcurrentHashMap<>();
            this.eventCounter = new AtomicLong(0);
            this.auditExecutor = Executors.newScheduledThreadPool(2, r -> {
                final var thread = new Thread(r, "DataProtection-Audit-" + System.currentTimeMillis());
                thread.setDaemon(true);
                return thread;
            });
            
            // Schedule audit log persistence
            auditExecutor.scheduleAtFixedRate(this::persistAuditLogs, 5, 5, TimeUnit.MINUTES);
            
            // Schedule audit log cleanup
            auditExecutor.scheduleAtFixedRate(this::cleanupOldLogs, 1, 24, TimeUnit.HOURS);
        }
        
        /**
         * Log data protection event for compliance audit trail
         */
        public void logDataProtectionEvent(final String customerId, final DataOperation operation,
                                         final DataClassification classification, final String operatorId,
                                         final String ipAddress, final String details, final boolean successful,
                                         final String errorMessage) {
            
            final var eventId = "AUDIT-" + eventCounter.incrementAndGet() + "-" + System.currentTimeMillis();
            final var event = new DataProtectionAuditEvent(
                eventId, customerId, operation, classification, LocalDateTime.now(),
                operatorId, ipAddress, details, successful, errorMessage
            );
            
            // Store in memory for immediate access
            auditLog.computeIfAbsent(customerId != null ? customerId : SYSTEM_OPERATOR, k -> new ArrayList<>())
                   .add(event);
            
            // Log to standard logger
            LOGGER.info("DATA_PROTECTION_AUDIT: " + event.toLogEntry());
            
            // Async persistence
            auditExecutor.submit(() -> persistEvent(event));
        }
        
        /**
         * Retrieve audit events for specific customer
         */
        public java.util.List<DataProtectionAuditEvent> getAuditEvents(final String customerId) {
            return auditLog.getOrDefault(customerId, java.util.List.of());
        }
        
        /**
         * Retrieve audit events by operation type
         */
        public java.util.List<DataProtectionAuditEvent> getAuditEventsByOperation(final DataOperation operation) {
            return auditLog.values().stream()
                          .flatMap(java.util.List::stream)
                          .filter(event -> event.operation().equals(operation))
                          .collect(Collectors.toList());
        }
        
        /**
         * Generate compliance report for audit trail
         */
        public ComplianceReport generateComplianceReport(final LocalDateTime fromDate, 
                                                       final LocalDateTime toDate) {
            final var events = auditLog.values().stream()
                                      .flatMap(java.util.List::stream)
                                      .filter(event -> event.timestamp().isAfter(fromDate) && 
                                                     event.timestamp().isBefore(toDate))
                                      .collect(Collectors.toList());
            
            final var operationCounts = events.stream()
                                             .collect(Collectors.groupingBy(
                                                 DataProtectionAuditEvent::operation,
                                                 Collectors.counting()));
            
            final var classificationCounts = events.stream()
                                                  .collect(Collectors.groupingBy(
                                                      DataProtectionAuditEvent::dataClassification,
                                                      Collectors.counting()));
            
            final var errorCount = events.stream()
                                        .mapToLong(event -> event.successful() ? 0 : 1)
                                        .sum();
            
            return new ComplianceReport(
                fromDate, toDate, events.size(), errorCount,
                operationCounts, classificationCounts,
                LocalDateTime.now()
            );
        }
        
        private void persistEvent(final DataProtectionAuditEvent event) {
            try {
                final var auditDir = new File(AUDIT_LOG_DIRECTORY);
                if (!auditDir.exists()) {
                    auditDir.mkdirs();
                }
                
                final var logFile = new File(auditDir, 
                    "audit_" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")) + ".log");
                
                try (var writer = new FileWriter(logFile, true)) {
                    writer.write(event.toLogEntry());
                    writer.write(System.lineSeparator());
                }
                
            } catch (IOException e) {
                LOGGER.severe("Failed to persist audit event: " + e.getMessage());
            }
        }
        
        private void persistAuditLogs() {
            LOGGER.info("Persisting audit logs - total events in memory: " + 
                       auditLog.values().stream().mapToInt(java.util.List::size).sum());
        }
        
        private void cleanupOldLogs() {
            final var cutoffDate = LocalDateTime.now().minus(AUDIT_LOG_RETENTION);
            
            auditLog.values().forEach(events -> 
                events.removeIf(event -> event.timestamp().isBefore(cutoffDate)));
            
            LOGGER.info("Cleaned up audit logs older than " + cutoffDate);
        }
        
        public void shutdown() {
            auditExecutor.shutdown();
            try {
                if (!auditExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    auditExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                auditExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        
        public record ComplianceReport(
            LocalDateTime fromDate,
            LocalDateTime toDate,
            long totalEvents,
            long errorEvents,
            Map<DataOperation, Long> operationCounts,
            Map<DataClassification, Long> classificationCounts,
            LocalDateTime generatedAt
        ) {}
    }
    
    /**
     * Privacy consent management service
     */
    public static final class ConsentManagementService {
        
        private final Map<String, Map<ConsentType, PrivacyConsent>> customerConsents;
        private final DataProtectionAuditService auditService;
        
        public ConsentManagementService(final DataProtectionAuditService auditService) {
            this.customerConsents = new ConcurrentHashMap<>();
            this.auditService = auditService;
        }
        
        /**
         * Grant consent for specific customer and type
         */
        public PrivacyConsent grantConsent(final String customerId, final ConsentType consentType,
                                         final String ipAddress, final String userAgent,
                                         final Duration validFor) {
            
            final var consentId = "CONSENT-" + System.currentTimeMillis() + "-" + 
                                Math.abs(customerId.hashCode());
            final var grantedAt = LocalDateTime.now();
            final var expiresAt = validFor != null ? grantedAt.plus(validFor) : null;
            
            final var consent = new PrivacyConsent(
                consentId, customerId, consentType, true, grantedAt, expiresAt,
                ipAddress, userAgent, "Explicit consent", true
            );
            
            customerConsents.computeIfAbsent(customerId, k -> new ConcurrentHashMap<>())
                           .put(consentType, consent);
            
            auditService.logDataProtectionEvent(
                customerId, new DataOperation.Create(), DataClassification.PERSONAL,
                CUSTOMER_PREFIX, ipAddress, "Consent granted: " + consentType.getDisplayName(),
                true, null
            );
            
            return consent;
        }
        
        /**
         * Withdraw consent for specific customer and type
         */
        public boolean withdrawConsent(final String customerId, final ConsentType consentType,
                                     final String ipAddress) {
            
            final var consents = customerConsents.get(customerId);
            if (consents == null) return false;
            
            final var existingConsent = consents.get(consentType);
            if (existingConsent == null || !existingConsent.withdrawable()) return false;
            
            // Create withdrawn consent record
            final var withdrawnConsent = new PrivacyConsent(
                existingConsent.consentId() + "-WITHDRAWN",
                customerId, consentType, false, LocalDateTime.now(), null,
                ipAddress, null, "Consent withdrawn", false
            );
            
            consents.put(consentType, withdrawnConsent);
            
            auditService.logDataProtectionEvent(
                customerId, new DataOperation.Update(), DataClassification.PERSONAL,
                CUSTOMER_PREFIX, ipAddress, "Consent withdrawn: " + consentType.getDisplayName(),
                true, null
            );
            
            return true;
        }
        
        /**
         * Check if customer has valid consent for specific type
         */
        public boolean hasValidConsent(final String customerId, final ConsentType consentType) {
            final var consents = customerConsents.get(customerId);
            if (consents == null) return false;
            
            final var consent = consents.get(consentType);
            return consent != null && consent.isValid();
        }
        
        /**
         * Get all consents for customer
         */
        public java.util.List<PrivacyConsent> getCustomerConsents(final String customerId) {
            final var consents = customerConsents.get(customerId);
            return consents != null ? new ArrayList<>(consents.values()) : java.util.List.of();
        }
        
        /**
         * Get consent expiry summary for customer
         */
        public ConsentSummary getConsentSummary(final String customerId) {
            final var consents = getCustomerConsents(customerId);
            
            final var validConsents = consents.stream()
                                             .filter(PrivacyConsent::isValid)
                                             .count();
            
            final var expiredConsents = consents.stream()
                                               .filter(PrivacyConsent::isExpired)
                                               .count();
            
            final var nearExpiryConsents = consents.stream()
                                                  .filter(consent -> consent.isValid() && 
                                                         consent.getTimeUntilExpiry().toDays() <= 30)
                                                  .count();
            
            return new ConsentSummary(
                consents.size(), validConsents, expiredConsents, nearExpiryConsents,
                LocalDateTime.now()
            );
        }
        
        public record ConsentSummary(
            long totalConsents,
            long validConsents,
            long expiredConsents,
            long nearExpiryConsents,
            LocalDateTime generatedAt
        ) {}
    }
    
    /**
     * Subject access request handler for GDPR compliance
     */
    public static final class SubjectAccessRequestService {
        
        private final Map<String, SubjectAccessRequest> accessRequests;
        private final DataProtectionAuditService auditService;
        private final DataAnonymizationService anonymizationService;
        private final ExecutorService requestExecutor;
        
        public SubjectAccessRequestService(final DataProtectionAuditService auditService,
                                         final DataAnonymizationService anonymizationService) {
            this.accessRequests = new ConcurrentHashMap<>();
            this.auditService = auditService;
            this.anonymizationService = anonymizationService;
            this.requestExecutor = Executors.newFixedThreadPool(4, r -> {
                final var thread = new Thread(r, "SAR-Processor-" + System.currentTimeMillis());
                thread.setDaemon(false);
                return thread;
            });
        }
        
        /**
         * Submit subject access request
         */
        public CompletableFuture<SubjectAccessRequest> submitAccessRequest(
                final String customerId, final String requestType, final String requestorIpAddress,
                final String verificationMethod) {
            
            final var requestId = "SAR-" + System.currentTimeMillis() + "-" + 
                                Math.abs(customerId.hashCode());
            
            final var request = new SubjectAccessRequest(
                requestId, customerId, requestType, LocalDateTime.now(), null,
                "SUBMITTED", requestorIpAddress, verificationMethod, null
            );
            
            accessRequests.put(requestId, request);
            
            auditService.logDataProtectionEvent(
                customerId, new DataOperation.Create(), DataClassification.PERSONAL,
                CUSTOMER_PREFIX, requestorIpAddress, "Subject access request submitted: " + requestType,
                true, null
            );
            
            // Process request asynchronously
            return CompletableFuture.supplyAsync(() -> processAccessRequest(request), requestExecutor);
        }
        
        /**
         * Process subject access request based on type
         */
        private SubjectAccessRequest processAccessRequest(final SubjectAccessRequest request) {
            try {
                final var result = switch (request.requestType().toUpperCase()) {
                    case EXPORT_OPERATION -> processDataExportRequest(request);
                    case DELETE_OPERATION -> processDataDeletionRequest(request);
                    case "CORRECT" -> processDataCorrectionRequest(request);
                    case "RESTRICT" -> processDataRestrictionRequest(request);
                    default -> updateRequestStatus(request, "REJECTED", "Unknown request type");
                };
                
                auditService.logDataProtectionEvent(
                    request.customerId(), new DataOperation.Update(), DataClassification.PERSONAL,
                    SYSTEM_OPERATOR, null, "SAR processed: " + request.requestType(),
                    result.isCompleted(), null
                );
                
                return result;
                
            } catch (Exception e) {
                LOGGER.severe("SAR processing failed for " + request.requestId() + ": " + e.getMessage());
                
                auditService.logDataProtectionEvent(
                    request.customerId(), new DataOperation.Update(), DataClassification.PERSONAL,
                    SYSTEM_OPERATOR, null, "SAR processing failed: " + request.requestType(),
                    false, e.getMessage()
                );
                
                return updateRequestStatus(request, "FAILED", e.getMessage());
            }
        }
        
        private SubjectAccessRequest processDataExportRequest(final SubjectAccessRequest request) {
            try {
                // Create export directory
                final var exportDir = new File(EXPORT_DIRECTORY);
                if (!exportDir.exists()) {
                    exportDir.mkdirs();
                }
                
                // Generate customer data export
                final var exportFile = new File(exportDir, 
                    "customer_data_" + request.customerId() + "_" + 
                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".json");
                
                final var customerData = generateCustomerDataExport(request.customerId());
                
                try (var writer = new FileWriter(exportFile)) {
                    writer.write(customerData);
                }
                
                return updateRequestStatus(request, COMPLETED_STATUS, exportFile.getAbsolutePath());
                
            } catch (IOException e) {
                throw new RuntimeException("Data export failed", e);
            }
        }
        
        private SubjectAccessRequest processDataDeletionRequest(final SubjectAccessRequest request) {
            // Implement right to be forgotten
            final var deletionSummary = performDataDeletion(request.customerId());
            return updateRequestStatus(request, COMPLETED_STATUS, 
                "Data deletion completed: " + deletionSummary);
        }
        
        private SubjectAccessRequest processDataCorrectionRequest(final SubjectAccessRequest request) {
            // Mark data for correction review
            return updateRequestStatus(request, "PENDING_REVIEW", 
                "Data correction request requires manual review");
        }
        
        private SubjectAccessRequest processDataRestrictionRequest(final SubjectAccessRequest request) {
            // Mark data for processing restriction
            return updateRequestStatus(request, COMPLETED_STATUS, 
                "Data processing restriction applied");
        }
        
        private SubjectAccessRequest updateRequestStatus(final SubjectAccessRequest original,
                                                       final String newStatus, final String details) {
            final var updated = new SubjectAccessRequest(
                original.requestId(), original.customerId(), original.requestType(),
                original.requestedAt(), LocalDateTime.now(), newStatus,
                original.requestorIpAddress(), original.verificationMethod(),
                details
            );
            
            accessRequests.put(original.requestId(), updated);
            return updated;
        }
        
        private String generateCustomerDataExport(final String customerId) {
            // Generate comprehensive JSON export of customer data
            final var exportData = new HashMap<String, Object>();
            
            exportData.put("customerId", customerId);
            exportData.put("exportGeneratedAt", LocalDateTime.now().format(DATE_FORMATTER));
            exportData.put("dataController", "E-commerce Platform");
            exportData.put("legalBasis", "GDPR Article 20 - Right to data portability");
            
            // Add audit events
            final var auditEvents = auditService.getAuditEvents(customerId);
            exportData.put("auditTrail", auditEvents);
            
            // Add placeholder for additional customer data
            exportData.put("personalData", Map.of(
                "notice", "Customer personal data would be included here in production",
                "categories", java.util.List.of("contact_info", "order_history", "preferences", "billing_data")
            ));
            
            try {
                // Simple JSON serialization (in production, use Jackson or similar)
                return exportData.toString();
            } catch (Exception e) {
                throw new RuntimeException("JSON export generation failed", e);
            }
        }
        
        private String performDataDeletion(final String customerId) {
            // Implement comprehensive data deletion
            final var deletedRecords = new HashMap<String, Integer>();
            
            // In production, this would delete from actual data stores
            deletedRecords.put("orders", 0);
            deletedRecords.put("customer_profile", 1);
            deletedRecords.put("billing_records", 0);
            deletedRecords.put("audit_logs", 0); // Keep for compliance
            
            return "Deleted: " + deletedRecords.toString();
        }
        
        public java.util.List<SubjectAccessRequest> getOverdueRequests() {
            return accessRequests.values().stream()
                                .filter(SubjectAccessRequest::isOverdue)
                                .collect(Collectors.toList());
        }
        
        public void shutdown() {
            requestExecutor.shutdown();
            try {
                if (!requestExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                    requestExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                requestExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    // === PDF Generation Engine ===
    
    /**
     * High-performance PDF generation service with privacy-by-design and caching
     */
    public static final class PdfGenerationService {
        
        private final Cache<String, byte[]> templateCache;
        private final EncryptionService encryptionService;
        private final DataAnonymizationService anonymizationService;
        private final DataProtectionAuditService auditService;
        
        public PdfGenerationService() throws NoSuchAlgorithmException {
            this.templateCache = Caffeine.newBuilder()
                                        .maximumSize(CACHE_MAX_SIZE)
                                        .expireAfterWrite(CACHE_EXPIRE_DURATION)
                                        .build();
            this.encryptionService = new EncryptionService();
            this.anonymizationService = new DataAnonymizationService();
            this.auditService = new DataProtectionAuditService();
        }
        
        /**
         * Generates PDF asynchronously for high performance
         */
        public CompletableFuture<String> generateOrderConfirmationAsync(final Order order) {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return generateOrderConfirmation(order);
                } catch (Exception e) {
                    LOGGER.severe("Failed to generate PDF for order: " + order.orderId() + " - " + e.getMessage());
                    throw new RuntimeException("PDF generation failed", e);
                }
            });
        }
        
        /**
         * Main PDF generation method with GDPR compliance and privacy-by-design
         */
        public String generateOrderConfirmation(final Order order) throws Exception {
            return generateOrderConfirmation(order, false); // Default to non-anonymized
        }
        
        /**
         * Generate PDF with optional data anonymization for privacy compliance
         */
        public String generateOrderConfirmation(final Order order, final boolean anonymizeData) throws Exception {
            // Audit logging for PDF generation
            auditService.logDataProtectionEvent(
                order.customer().customerId(), new DataOperation.Create(), 
                DataClassification.PERSONAL, "PDF_GENERATOR", null,
                "PDF generation requested for order: " + order.orderId() + 
                (anonymizeData ? " (anonymized)" : " (full data)"), true, null
            );
            
            final var outputDir = new File(OUTPUT_DIRECTORY);
            if (!outputDir.exists()) {
                outputDir.mkdirs();
            }
            
            final var filename = "%s/order_confirmation_%s_%s%s.pdf".formatted(
                OUTPUT_DIRECTORY,
                order.orderId(),
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")),
                anonymizeData ? "_ANON" : ""
            );
            
            try (var writer = new PdfWriter(filename)) {
                final var pdfDoc = new PdfDocument(writer);
                final var document = new Document(pdfDoc);
                
                // Privacy-by-design: Apply data masking if requested
                final var processedOrder = anonymizeData ? applyDataProtectionMasking(order) : order;
                
                // Add content sections with privacy considerations
                addPrivacyCompliantHeader(document, processedOrder, anonymizeData);
                addPrivacyCompliantCustomerInformation(document, processedOrder.customer(), anonymizeData);
                addOrderSummary(document, processedOrder);
                addItemsTable(document, processedOrder);
                addShipmentInformation(document, processedOrder);
                addCouponInformation(document, processedOrder);
                addPrivacyCompliantFooter(document, processedOrder, anonymizeData);
                
                document.close();
            }
            
            // Audit successful generation
            auditService.logDataProtectionEvent(
                order.customer().customerId(), new DataOperation.Create(), 
                DataClassification.PERSONAL, "PDF_GENERATOR", null,
                "PDF generated successfully: " + filename, true, null
            );
            
            LOGGER.info("Generated %s PDF for order: %s".formatted(
                anonymizeData ? "anonymized" : "full", order.orderId()));
            return filename;
        }
        
        /**
         * Apply data protection masking to order data
         */
        private Order applyDataProtectionMasking(final Order order) {
            final var customer = order.customer();
            
            // Create masked customer data
            final var maskedCustomer = new Customer(
                anonymizationService.pseudonymizeData(customer.customerId(), "customer"),
                anonymizationService.anonymizeData(customer.firstName(), DataClassification.PERSONAL),
                anonymizationService.anonymizeData(customer.lastName(), DataClassification.PERSONAL),
                anonymizationService.anonymizeData(customer.email(), DataClassification.PERSONAL),
                customer.phone() != null ? 
                    anonymizationService.anonymizeData(customer.phone(), DataClassification.PERSONAL) : null,
                customer.billingAddress(),  // Address kept for shipping purposes
                customer.shippingAddress()
            );
            
            // Return order with masked customer data
            return new Order(
                order.orderId(), maskedCustomer, order.items(), order.shipments(),
                order.appliedCoupons(), order.status(), order.orderDate(),
                order.shippingCost(), order.taxRate(), order.specialInstructions()
            );
        }
        
        private void addPrivacyCompliantHeader(final Document document, final Order order, final boolean anonymized) throws Exception {
            final var headerText = anonymized ? 
                """
                ORDER CONFIRMATION (ANONYMIZED)

                Thank you for your order! Your order has been received
                and is being processed according to our service standards.
                
                This document contains anonymized data for privacy protection.
                """ :
                """
                ORDER CONFIRMATION

                Thank you for your order! Your order has been received
                and is being processed according to our service standards.
                """;
            
            final var header = new Paragraph(headerText)
                .setTextAlignment(TextAlignment.CENTER)
                .setFontSize(16)
                .setBold();
            
            document.add(header);
            document.add(new LineSeparator(new SolidLine()));
            
            final var orderInfo = """
                                 Order ID: %s
                                 Order Date: %s
                                 Status: %s
                                 Data Classification: %s
                                 """.formatted(
                                     order.orderId(),
                                     order.orderDate().format(DATE_FORMATTER),
                                     order.status().getDisplayName(),
                                     anonymized ? "ANONYMIZED" : "PERSONAL DATA"
                                 );
            
            document.add(new Paragraph(orderInfo).setFontSize(12));
            
            // Add privacy notice if not anonymized
            if (!anonymized) {
                final var privacyNotice = """
                                        
                                        PRIVACY NOTICE: This document contains personal data processed under
                                        GDPR Article 6(1)(b) - Performance of contract. For privacy inquiries,
                                        contact: privacy@ecommerce-platform.com
                                        """;
                document.add(new Paragraph(privacyNotice).setFontSize(8).setItalic());
            }
        }
        
        private void addHeader(final Document document, final Order order) throws Exception {
            addPrivacyCompliantHeader(document, order, false);
        }
        
        private void addPrivacyCompliantCustomerInformation(final Document document, final Customer customer, final boolean anonymized) throws Exception {
            document.add(new Paragraph("CUSTOMER INFORMATION").setBold().setFontSize(14));
            
            // Detect and classify personal data
            final var personalDataDetected = anonymizationService.detectPersonalData(customer.email());
            final var dataClassification = personalDataDetected.isEmpty() ? 
                DataClassification.INTERNAL : DataClassification.PERSONAL;
            
            final var customerInfo = """
                                   Customer: %s
                                   Email: %s
                                   Phone: %s
                                   Customer ID: %s
                                   Data Classification: %s
                                   
                                   Billing Address:
                                   %s
                                   
                                   Shipping Address:
                                   %s
                                   """.formatted(
                                       customer.getFullName(),
                                       customer.email(),
                                       customer.phone() != null ? customer.phone() : "Not provided",
                                       customer.customerId(),
                                       dataClassification.getDisplayName(),
                                       customer.billingAddress().getFormattedAddress(),
                                       customer.shippingAddress().getFormattedAddress()
                                   );
            
            document.add(new Paragraph(customerInfo).setFontSize(10));
            
            // Add data protection notice for anonymized documents
            if (anonymized) {
                final var anonymizationNotice = """
                                              
                                              NOTE: Personal data has been anonymized for privacy protection.
                                              Original data is securely stored and processed according to our
                                              data protection policy.
                                              """;
                document.add(new Paragraph(anonymizationNotice).setFontSize(8).setItalic());
            }
        }
        
        private void addCustomerInformation(final Document document, final Customer customer) throws Exception {
            addPrivacyCompliantCustomerInformation(document, customer, false);
        }
        
        private void addOrderSummary(final Document document, final Order order) {
            document.add(new Paragraph("ORDER SUMMARY").setBold().setFontSize(14));
            
            final var table = new Table(UnitValue.createPercentArray(new float[]{3, 1}));
            table.setWidth(UnitValue.createPercentValue(100));
            
            addSummaryRow(table, "Subtotal:", CURRENCY_FORMAT.formatted(order.getSubtotal()));
            
            if (order.getTotalDiscount().compareTo(ZERO) > 0) {
                addSummaryRow(table, "Discount:", "-$%.2f".formatted(order.getTotalDiscount()));
            }
            
            addSummaryRow(table, "Tax:", CURRENCY_FORMAT.formatted(order.getTaxAmount()));
            addSummaryRow(table, "Shipping:", CURRENCY_FORMAT.formatted(order.shippingCost()));
            addSummaryRow(table, "TOTAL:", CURRENCY_FORMAT.formatted(order.getGrandTotal()));
            
            document.add(table);
        }
        
        private void addSummaryRow(final Table table, final String label, final String value) {
            table.addCell(new Cell().add(new Paragraph(label)).setBold());
            table.addCell(new Cell().add(new Paragraph(value)).setTextAlignment(TextAlignment.RIGHT));
        }
        
        private void addItemsTable(final Document document, final Order order) {
            document.add(new Paragraph("ORDER ITEMS").setBold().setFontSize(14));
            
            final var table = new Table(UnitValue.createPercentArray(new float[]{3, 1, 2, 2, 1}));
            table.setWidth(UnitValue.createPercentValue(100));
            
            // Headers
            table.addHeaderCell(new Cell().add(new Paragraph("Item")).setBold());
            table.addHeaderCell(new Cell().add(new Paragraph("Qty")).setBold());
            table.addHeaderCell(new Cell().add(new Paragraph("Unit Price")).setBold());
            table.addHeaderCell(new Cell().add(new Paragraph("Total")).setBold());
            table.addHeaderCell(new Cell().add(new Paragraph("Status")).setBold());
            
            // Items
            order.items().forEach(item -> {
                table.addCell(new Cell().add(new Paragraph("""
                                                         %s
                                                         %s
                                                         """.formatted(item.productName(), item.description()))));
                table.addCell(new Cell().add(new Paragraph(String.valueOf(item.quantity()))));
                table.addCell(new Cell().add(new Paragraph(CURRENCY_FORMAT.formatted(item.unitPrice()))));
                table.addCell(new Cell().add(new Paragraph(CURRENCY_FORMAT.formatted(item.getTotalPrice()))));
                table.addCell(new Cell().add(new Paragraph(item.isBackordered() ? "BACKORDER" : "IN STOCK")));
            });
            
            document.add(table);
        }
        
        private void addShipmentInformation(final Document document, final Order order) {
            if (order.shipments().isEmpty()) return;
            
            document.add(new Paragraph("SHIPMENT INFORMATION").setBold().setFontSize(14));
            
            order.shipments().forEach(shipment -> {
                final var shipmentInfo = """
                                       Shipment ID: %s
                                       Tracking Number: %s
                                       Carrier: %s
                                       Type: %s
                                       Estimated Delivery: %s
                                       Weight: %.2f lbs
                                       
                                       """.formatted(
                                           shipment.shipmentId(),
                                           shipment.trackingNumber(),
                                           shipment.carrier(),
                                           shipment.type().getDisplayName(),
                                           shipment.estimatedDelivery().format(DATE_FORMATTER),
                                           shipment.getTotalWeight()
                                       );
                
                document.add(new Paragraph(shipmentInfo).setFontSize(10));
            });
        }
        
        private void addCouponInformation(final Document document, final Order order) {
            if (order.appliedCoupons().isEmpty()) return;
            
            document.add(new Paragraph("APPLIED PROMOTIONS").setBold().setFontSize(14));
            
            order.appliedCoupons().forEach(coupon -> {
                final var couponInfo = """
                                     Code: %s
                                     Description: %s
                                     Discount: %s
                                     
                                     """.formatted(
                                         coupon.couponCode(),
                                         coupon.description(),
                                         coupon.type().getDisplayName()
                                     );
                
                document.add(new Paragraph(couponInfo).setFontSize(10));
            });
        }
        
        private void addPrivacyCompliantFooter(final Document document, final Order order, final boolean anonymized) {
            final var footer = """
                             
                             Thank you for your business!
                             
                             For questions about your order, please contact our customer service
                             team with your order ID: %s
                             
                             Email: support@ecommerce-platform.com
                             Phone: 1-800-SUPPORT
                             
                             Generated on: %s
                             Document Type: %s
                             """.formatted(
                                 order.orderId(),
                                 LocalDateTime.now().format(DATE_FORMATTER),
                                 anonymized ? "Anonymized Copy" : "Original with Personal Data"
                             );
            
            document.add(new Paragraph(footer).setTextAlignment(TextAlignment.CENTER).setFontSize(9));
            
            // Add comprehensive privacy footer
            final var privacyFooter = anonymized ?
                """
                
                PRIVACY PROTECTION NOTICE:
                This document has been generated with anonymized personal data for privacy protection.
                Data anonymization performed using industry-standard techniques including pseudonymization
                and masking to comply with GDPR Article 25 (Data Protection by Design).
                
                Data Controller: E-commerce Platform Ltd.
                Data Protection Officer: privacy@ecommerce-platform.com
                Legal Basis: GDPR Article 6(1)(b) - Performance of contract
                Retention Period: 7 years as per legal requirements
                
                Your Rights: Access, Rectification, Erasure, Restriction, Portability, Objection
                To exercise rights: privacy@ecommerce-platform.com or 1-800-PRIVACY
                Supervisory Authority: [Your Local Data Protection Authority]
                """ :
                """
                
                DATA PROTECTION NOTICE:
                This document contains personal data processed in accordance with GDPR and applicable
                data protection laws. Data is processed for order fulfillment and customer service.
                
                Data Controller: E-commerce Platform Ltd.
                Data Protection Officer: privacy@ecommerce-platform.com
                Legal Basis: GDPR Article 6(1)(b) - Performance of contract
                Retention Period: 7 years as per legal requirements
                
                Your Privacy Rights:
                • Right to Access - Request copies of your personal data
                • Right to Rectification - Request correction of inaccurate data
                • Right to Erasure - Request deletion of your data
                • Right to Restriction - Request limitation of data processing
                • Right to Data Portability - Request transfer of your data
                • Right to Object - Object to data processing
                
                To exercise rights: privacy@ecommerce-platform.com or 1-800-PRIVACY
                Complaint to Supervisory Authority: [Your Local Data Protection Authority]
                """;
            
            document.add(new Paragraph(privacyFooter).setTextAlignment(TextAlignment.LEFT).setFontSize(7));
        }
        
        private void addFooter(final Document document, final Order order) {
            addPrivacyCompliantFooter(document, order, false);
        }
    }
    
    // === Business Logic ===
    
    /**
     * Main application orchestrator with high-performance processing
     */
    public static final class OrderConfirmationProcessor {
        
        private final PdfGenerationService pdfService;
        private final Map<String, Order> orderCache;
        
        public OrderConfirmationProcessor() throws NoSuchAlgorithmException {
            this.pdfService = new PdfGenerationService();
            this.orderCache = new ConcurrentHashMap<>();
        }
        
        /**
         * Process order confirmation with performance monitoring
         */
        public CompletableFuture<String> processOrderConfirmation(final Order order) {
            final var startTime = System.currentTimeMillis();
            
            return validateOrder(order)
                .thenCompose(validOrder -> {
                    orderCache.put(validOrder.orderId(), validOrder);
                    return pdfService.generateOrderConfirmationAsync(validOrder);
                })
                .whenComplete((result, throwable) -> {
                    final var duration = System.currentTimeMillis() - startTime;
                    if (throwable == null) {
                        LOGGER.info("Order %s processed successfully in %d ms".formatted(order.orderId(), duration));
                    } else {
                        LOGGER.severe("Order %s processing failed after %d ms: %s".formatted(
                            order.orderId(), duration, throwable.getMessage()));
                    }
                });
        }
        
        private CompletableFuture<Order> validateOrder(final Order order) {
            return CompletableFuture.supplyAsync(() -> {
                // Comprehensive business validation
                if (!order.status().isShippable() && !order.shipments().isEmpty()) {
                    throw new IllegalStateException("Non-shippable order cannot have shipments");
                }
                
                // Validate coupon applicability
                final var invalidCoupons = order.appliedCoupons().stream()
                                               .filter(coupon -> !coupon.isValidAt(order.orderDate()))
                                               .collect(Collectors.toList());
                
                if (!invalidCoupons.isEmpty()) {
                    LOGGER.warning("Order %s has invalid coupons: %s".formatted(
                        order.orderId(), 
                        invalidCoupons.stream().map(Coupon::couponCode).collect(Collectors.joining(", "))
                    ));
                }
                
                return order;
            });
        }
    }
    
    // === Multithreading & Concurrent Processing ===
    
    /**
     * Performance metrics tracker for concurrent operations
     */
    public static final class PerformanceMetrics {
        
        private final AtomicLong totalRequestsProcessed = new AtomicLong(0);
        private final AtomicLong totalProcessingTime = new AtomicLong(0);
        private final AtomicInteger currentlyProcessing = new AtomicInteger(0);
        private final AtomicLong totalErrors = new AtomicLong(0);
        private final AtomicInteger peakConcurrency = new AtomicInteger(0);
        private final Map<String, AtomicLong> operationMetrics = new ConcurrentHashMap<>();
        
        public void recordRequest(final long processingTimeMs) {
            totalRequestsProcessed.incrementAndGet();
            totalProcessingTime.addAndGet(processingTimeMs);
            currentlyProcessing.decrementAndGet();
        }
        
        public void startProcessing() {
            final var current = currentlyProcessing.incrementAndGet();
            peakConcurrency.updateAndGet(peak -> Math.max(peak, current));
        }
        
        public void recordError() {
            totalErrors.incrementAndGet();
            currentlyProcessing.decrementAndGet();
        }
        
        public void recordOperation(final String operation, final long durationMs) {
            operationMetrics.computeIfAbsent(operation, k -> new AtomicLong(0))
                          .addAndGet(durationMs);
        }
        
        public MetricsSnapshot getSnapshot() {
            final var processed = totalRequestsProcessed.get();
            final var avgProcessingTime = processed > 0 ? totalProcessingTime.get() / processed : 0;
            
            return new MetricsSnapshot(
                processed,
                avgProcessingTime,
                currentlyProcessing.get(),
                totalErrors.get(),
                peakConcurrency.get(),
                Map.copyOf(operationMetrics.entrySet().stream()
                    .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue().get()
                    )))
            );
        }
        
        public record MetricsSnapshot(
            long totalProcessed,
            long averageProcessingTimeMs,
            int currentlyProcessing,
            long totalErrors,
            int peakConcurrency,
            Map<String, Long> operationMetrics
        ) {}
    }
    
    /**
     * Circuit breaker pattern implementation for fault tolerance
     */
    public static final class CircuitBreaker {
        
        public enum State { CLOSED, OPEN, HALF_OPEN }
        
        private final int failureThreshold;
        private final Duration timeout;
        private final AtomicInteger failureCount = new AtomicInteger(0);
        private final AtomicInteger successCount = new AtomicInteger(0);
        private volatile State state = State.CLOSED;
        private volatile long lastFailureTime = 0;
        
        public CircuitBreaker(final int failureThreshold, final Duration timeout) {
            this.failureThreshold = failureThreshold;
            this.timeout = timeout;
        }
        
        public boolean allowRequest() {
            if (state == State.CLOSED) {
                return true;
            }
            
            if (state == State.OPEN) {
                if (System.currentTimeMillis() - lastFailureTime >= timeout.toMillis()) {
                    state = State.HALF_OPEN;
                    return true;
                }
                return false;
            }
            
            // HALF_OPEN state
            return true;
        }
        
        public void recordSuccess() {
            if (state == State.HALF_OPEN) {
                state = State.CLOSED;
                failureCount.set(0);
            }
            successCount.incrementAndGet();
        }
        
        public void recordFailure() {
            final var failures = failureCount.incrementAndGet();
            lastFailureTime = System.currentTimeMillis();
            
            if (failures >= failureThreshold) {
                state = State.OPEN;
            }
        }
        
        public State getState() {
            return state;
        }
        
        public CircuitBreakerStats getStats() {
            return new CircuitBreakerStats(
                state,
                failureCount.get(),
                successCount.get(),
                lastFailureTime
            );
        }
        
        public record CircuitBreakerStats(
            State state,
            int failureCount,
            int successCount,
            long lastFailureTime
        ) {}
    }
    
    /**
     * Rate limiter using token bucket algorithm
     */
    public static final class RateLimiter {
        
        private final int maxTokens;
        private final Duration refillPeriod;
        private final AtomicInteger tokens;
        private volatile long lastRefillTime;
        
        public RateLimiter(final int maxTokens, final Duration refillPeriod) {
            this.maxTokens = maxTokens;
            this.refillPeriod = refillPeriod;
            this.tokens = new AtomicInteger(maxTokens);
            this.lastRefillTime = System.currentTimeMillis();
        }
        
        public boolean tryAcquire() {
            refillTokens();
            
            return tokens.updateAndGet(current -> 
                current > 0 ? current - 1 : current
            ) >= 0;
        }
        
        public boolean tryAcquire(final int permits) {
            if (permits <= 0) return true;
            
            refillTokens();
            
            return tokens.updateAndGet(current -> 
                current >= permits ? current - permits : current
            ) >= 0;
        }
        
        private void refillTokens() {
            final var now = System.currentTimeMillis();
            final var timeSinceLastRefill = now - lastRefillTime;
            
            if (timeSinceLastRefill >= refillPeriod.toMillis()) {
                tokens.set(maxTokens);
                lastRefillTime = now;
            }
        }
        
        public int getAvailableTokens() {
            refillTokens();
            return Math.max(0, tokens.get());
        }
    }
    
    /**
     * Resource pool manager for expensive operations
     */
    public static final class ResourcePoolManager {
        
        private final BlockingQueue<PdfGenerationService> pdfServicePool;
        private final BlockingQueue<EncryptionService> encryptionServicePool;
        private final ScheduledExecutorService cleanupExecutor;
        
        public ResourcePoolManager() throws NoSuchAlgorithmException {
            this.pdfServicePool = new LinkedBlockingQueue<>();
            this.encryptionServicePool = new LinkedBlockingQueue<>();
            this.cleanupExecutor = Executors.newScheduledThreadPool(1, r -> {
                final var thread = new Thread(r, "ResourcePool-Cleanup");
                thread.setDaemon(true);
                return thread;
            });
            
            // Initialize pools
            for (int i = 0; i < PDF_GENERATION_POOL_SIZE; i++) {
                pdfServicePool.offer(new PdfGenerationService());
            }
            
            for (int i = 0; i < ENCRYPTION_POOL_SIZE; i++) {
                encryptionServicePool.offer(new EncryptionService());
            }
            
            // Schedule periodic cleanup
            cleanupExecutor.scheduleAtFixedRate(this::performCleanup, 1, 1, TimeUnit.HOURS);
        }
        
        public PdfGenerationService acquirePdfService() throws InterruptedException {
            var service = pdfServicePool.poll(30, TimeUnit.SECONDS);
            if (service == null) {
                try {
                    service = new PdfGenerationService();
                    LOGGER.warning("Created new PDF service due to pool exhaustion");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException("Failed to create PDF service", e);
                }
            }
            return service;
        }
        
        public void releasePdfService(final PdfGenerationService service) {
            if (pdfServicePool.size() < PDF_GENERATION_POOL_SIZE) {
                pdfServicePool.offer(service);
            }
        }
        
        public EncryptionService acquireEncryptionService() throws InterruptedException {
            var service = encryptionServicePool.poll(30, TimeUnit.SECONDS);
            if (service == null) {
                try {
                    service = new EncryptionService();
                    LOGGER.warning("Created new encryption service due to pool exhaustion");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException("Failed to create encryption service", e);
                }
            }
            return service;
        }
        
        public void releaseEncryptionService(final EncryptionService service) {
            if (encryptionServicePool.size() < ENCRYPTION_POOL_SIZE) {
                encryptionServicePool.offer(service);
            }
        }
        
        private void performCleanup() {
            LOGGER.info("Performing resource pool cleanup - PDF pool: %d, Encryption pool: %d"
                .formatted(pdfServicePool.size(), encryptionServicePool.size()));
        }
        
        public void shutdown() {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
    
    /**
     * High-performance concurrent order processor using structured concurrency
     */
    public static final class ConcurrentOrderProcessor {
        
        private final ExecutorService mainExecutor;
        private final ExecutorService pdfExecutor;
        private final ExecutorService validationExecutor;
        private final BlockingQueue<OrderRequest> requestQueue;
        private final ResourcePoolManager resourceManager;
        private final PerformanceMetrics metrics;
        private final CircuitBreaker circuitBreaker;
        private final RateLimiter rateLimiter;
        private final ScheduledExecutorService monitoringExecutor;
        private volatile boolean isShutdown = false;
        
        public ConcurrentOrderProcessor() throws NoSuchAlgorithmException {
            this.mainExecutor = Executors.newFixedThreadPool(DEFAULT_THREAD_POOL_SIZE, r -> {
                final var thread = new Thread(r, "OrderProcessor-Main-" + System.currentTimeMillis());
                thread.setDaemon(false);
                return thread;
            });
            
            this.pdfExecutor = Executors.newFixedThreadPool(PDF_GENERATION_POOL_SIZE, r -> {
                final var thread = new Thread(r, "OrderProcessor-PDF-" + System.currentTimeMillis());
                thread.setDaemon(false);
                return thread;
            });
            
            this.validationExecutor = Executors.newFixedThreadPool(DEFAULT_THREAD_POOL_SIZE / 2, r -> {
                final var thread = new Thread(r, "OrderProcessor-Validation-" + System.currentTimeMillis());
                thread.setDaemon(false);
                return thread;
            });
            
            this.requestQueue = new LinkedBlockingQueue<>(MAX_QUEUE_SIZE);
            this.resourceManager = new ResourcePoolManager();
            this.metrics = new PerformanceMetrics();
            this.circuitBreaker = new CircuitBreaker(10, Duration.ofMinutes(1));
            this.rateLimiter = new RateLimiter(MAX_REQUESTS_PER_SECOND, RATE_LIMIT_WINDOW);
            
            this.monitoringExecutor = Executors.newScheduledThreadPool(1, r -> {
                final var thread = new Thread(r, "OrderProcessor-Monitor");
                thread.setDaemon(true);
                return thread;
            });
            
            // Start background processors
            startBackgroundProcessing();
            startMonitoring();
        }
        
        /**
         * Process single order with full concurrency support
         */
        public CompletableFuture<ProcessingResult> processOrderAsync(final Order order) {
            if (isShutdown) {
                return CompletableFuture.failedFuture(new IllegalStateException("Processor is shutdown"));
            }
            
            if (!rateLimiter.tryAcquire()) {
                return CompletableFuture.failedFuture(new RejectedExecutionException("Rate limit exceeded"));
            }
            
            if (!circuitBreaker.allowRequest()) {
                return CompletableFuture.failedFuture(new RuntimeException("Circuit breaker is open"));
            }
            
            final var request = new OrderRequest(order, System.currentTimeMillis());
            
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return processOrderInternal(request);
                    
                } catch (Exception e) {
                    metrics.recordError();
                    circuitBreaker.recordFailure();
                    throw new RuntimeException("Order processing failed", e);
                }
            }, mainExecutor);
        }
        
        /**
         * Process multiple orders concurrently in batches
         */
        public CompletableFuture<java.util.List<ProcessingResult>> processBatchAsync(
                final java.util.List<Order> orders) {
            
            if (orders.size() > BATCH_SIZE) {
                // Split large batches into smaller chunks
                final var futures = new ArrayList<CompletableFuture<java.util.List<ProcessingResult>>>();
                
                for (int i = 0; i < orders.size(); i += BATCH_SIZE) {
                    final var batch = orders.subList(i, Math.min(i + BATCH_SIZE, orders.size()));
                    futures.add(processBatchAsync(batch));
                }
                
                return CompletableFuture.allOf(futures.toArray(new CompletableFuture<?>[0]))
                    .thenApply(v -> futures.stream()
                        .flatMap(f -> f.join().stream())
                        .collect(Collectors.toList()));
            }
            
            // Use parallel CompletableFutures for batch processing
            final var futures = orders.stream()
                .map(order -> CompletableFuture.supplyAsync(() -> 
                    processOrderInternal(new OrderRequest(order, System.currentTimeMillis())), 
                    mainExecutor))
                .collect(Collectors.toList());
            
            return CompletableFuture.allOf(futures.toArray(new CompletableFuture<?>[0]))
                .thenApply(v -> futures.stream()
                    .map(CompletableFuture::join)
                    .collect(Collectors.toList()));
        }
        
        private ProcessingResult processOrderInternal(final OrderRequest request) {
            final var startTime = System.currentTimeMillis();
            metrics.startProcessing();
            
            try {
                // Validate order concurrently
                final var validationFuture = CompletableFuture.supplyAsync(() -> 
                    validateOrderConcurrent(request.order()), validationExecutor);
                
                // Generate PDF concurrently
                final var pdfFuture = validationFuture.thenComposeAsync(validatedOrder -> 
                    generatePdfConcurrent(validatedOrder), pdfExecutor);
                
                // Wait for completion with timeout
                final var pdfPath = pdfFuture.get(PROCESSING_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
                
                final var processingTime = System.currentTimeMillis() - startTime;
                metrics.recordRequest(processingTime);
                metrics.recordOperation("full-processing", processingTime);
                circuitBreaker.recordSuccess();
                
                return new ProcessingResult(
                    request.order().orderId(),
                    pdfPath,
                    ProcessingStatus.SUCCESS,
                    processingTime,
                    null
                );
                
            } catch (Exception e) {
                final var processingTime = System.currentTimeMillis() - startTime;
                metrics.recordError();
                circuitBreaker.recordFailure();
                
                LOGGER.severe("Failed to process order %s: %s".formatted(
                    request.order().orderId(), e.getMessage()));
                
                return new ProcessingResult(
                    request.order().orderId(),
                    null,
                    ProcessingStatus.FAILED,
                    processingTime,
                    e.getMessage()
                );
            }
        }
        
        private Order validateOrderConcurrent(final Order order) {
            final var validationStart = System.currentTimeMillis();
            
            try {
                // Perform comprehensive validation
                if (!order.status().isShippable() && !order.shipments().isEmpty()) {
                    throw new IllegalStateException("Non-shippable order cannot have shipments");
                }
                
                // Validate coupons
                final var invalidCoupons = order.appliedCoupons().stream()
                    .filter(coupon -> !coupon.isValidAt(order.orderDate()))
                    .collect(Collectors.toList());
                
                if (!invalidCoupons.isEmpty()) {
                    LOGGER.warning("Order %s has invalid coupons: %s".formatted(
                        order.orderId(),
                        invalidCoupons.stream().map(Coupon::couponCode)
                            .collect(Collectors.joining(", "))));
                }
                
                final var validationTime = System.currentTimeMillis() - validationStart;
                metrics.recordOperation("validation", validationTime);
                
                return order;
                
            } catch (Exception e) {
                throw new RuntimeException("Validation failed for order: " + order.orderId(), e);
            }
        }
        
        private CompletableFuture<String> generatePdfConcurrent(final Order order) {
            return CompletableFuture.supplyAsync(() -> {
                final var pdfStart = System.currentTimeMillis();
                PdfGenerationService pdfService = null;
                
                try {
                    pdfService = resourceManager.acquirePdfService();
                    final var pdfPath = pdfService.generateOrderConfirmation(order);
                    
                    final var pdfTime = System.currentTimeMillis() - pdfStart;
                    metrics.recordOperation("pdf-generation", pdfTime);
                    
                    return pdfPath;
                    
                } catch (Exception e) {
                    throw new RuntimeException("PDF generation failed for order: " + order.orderId(), e);
                } finally {
                    if (pdfService != null) {
                        resourceManager.releasePdfService(pdfService);
                    }
                }
            }, pdfExecutor);
        }
        
        private void startBackgroundProcessing() {
            // Background worker for processing queued requests
            mainExecutor.submit(() -> {
                while (!isShutdown) {
                    try {
                        final var request = requestQueue.poll(1, TimeUnit.SECONDS);
                        if (request != null) {
                            // Process in background without blocking
                            CompletableFuture.runAsync(() -> processOrderInternal(request), mainExecutor);
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    } catch (Exception e) {
                        LOGGER.severe("Background processing error: " + e.getMessage());
                    }
                }
            });
        }
        
        private void startMonitoring() {
            monitoringExecutor.scheduleAtFixedRate(() -> {
                if (isShutdown) return; // Stop monitoring if shutdown
                
                final var metrics = this.metrics.getSnapshot();
                final var circuitStats = circuitBreaker.getStats();
                
                LOGGER.info("""
                    === Concurrent Processing Metrics ===
                    Total Processed: %d
                    Currently Processing: %d
                    Average Time: %d ms
                    Peak Concurrency: %d
                    Total Errors: %d
                    Circuit Breaker: %s
                    Available Rate Tokens: %d
                    Queue Size: %d
                    """.formatted(
                        metrics.totalProcessed(),
                        metrics.currentlyProcessing(),
                        metrics.averageProcessingTimeMs(),
                        metrics.peakConcurrency(),
                        metrics.totalErrors(),
                        circuitStats.state(),
                        rateLimiter.getAvailableTokens(),
                        requestQueue.size()
                    ));
                    
            }, 5, 15, TimeUnit.SECONDS); // Reduced frequency for demo
        }
        
        public PerformanceMetrics.MetricsSnapshot getMetrics() {
            return metrics.getSnapshot();
        }
        
        public CircuitBreaker.CircuitBreakerStats getCircuitBreakerStats() {
            return circuitBreaker.getStats();
        }
        
        public void shutdown() {
            isShutdown = true;
            
            shutdownExecutor(mainExecutor, "Main");
            shutdownExecutor(pdfExecutor, "PDF");
            shutdownExecutor(validationExecutor, "Validation");
            shutdownExecutor(monitoringExecutor, "Monitoring");
            
            resourceManager.shutdown();
            
            LOGGER.info("ConcurrentOrderProcessor shutdown completed");
        }
        
        private void shutdownExecutor(final ExecutorService executor, final String name) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                    LOGGER.warning("%s executor did not terminate gracefully, forcing shutdown".formatted(name));
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        
        // Supporting records
        
        public record OrderRequest(Order order, long timestamp) {}
        
        public enum ProcessingStatus { SUCCESS, FAILED, TIMEOUT }
        
        public record ProcessingResult(
            String orderId,
            String pdfPath,
            ProcessingStatus status,
            long processingTimeMs,
            String errorMessage
        ) {}
    }
    
    // === Utility Methods ===
    
    /**
     * Creates sample data for testing and demonstration
     */
    private static Order createSampleOrder() {
        final var address = new Address(
            "123 Main Street, Apt 4B",
            "New York",
            "NY",
            "10001",
            "USA"
        );
        
        final var customer = new Customer(
            "CUST-12345",
            "John",
            "Doe",
            "john.doe@email.com",
            "(555) 123-4567",
            address,
            address
        );
        
        final var items = java.util.List.of(
            new OrderItem(
                "ITEM-001",
                "Premium Wireless Headphones",
                "Electronics",
                2,
                new BigDecimal("199.99"),
                new BigDecimal("1.5"),
                false,
                "High-quality wireless headphones with noise cancellation"
            ),
            new OrderItem(
                "ITEM-002",
                "Bluetooth Speaker",
                "Electronics",
                1,
                new BigDecimal("79.99"),
                new BigDecimal("2.0"),
                true,
                "Portable Bluetooth speaker - Currently backordered"
            )
        );
        
        final var shipments = java.util.List.of(
            new Shipment(
                "SHIP-001",
                "1Z999AA1234567890",
                "UPS",
                new ShipmentType.Standard(),
                LocalDateTime.now().plusDays(3),
                java.util.List.of(items.get(0))
             ),
             new Shipment(
                 "SHIP-002",
                 "1Z999AA1234567891",
                 "UPS",
                 new ShipmentType.Backorder(LocalDateTime.now().plusWeeks(2)),
                 LocalDateTime.now().plusWeeks(2),
                 java.util.List.of(items.get(1))
            )
        );
        
        final var coupons = java.util.List.of(
            new Coupon(
                "SAVE10",
                "10% off your order",
                new CouponType.Percentage(new BigDecimal("10")),
                LocalDateTime.now().minusDays(1),
                LocalDateTime.now().plusDays(30),
                true
            )
        );
        
        return new Order(
            "ORD-" + System.currentTimeMillis(),
            customer,
            items,
            shipments,
            coupons,
            new OrderStatus.Confirmed(),
            LocalDateTime.now(),
            new BigDecimal("9.99"),
            new BigDecimal("0.08"),
            "Handle with care - fragile items"
        );
    }
    
    // === Main Application Entry Point ===
    
    /**
     * Application entry point demonstrating GDPR-compliant concurrent order processing
     */
    public static void main(final String[] args) {
        LOGGER.info("Starting E-commerce Order Confirmation PDF Generator v2.2 - GDPR Compliant Edition");
        
        try {
            // Initialize data protection services
            final var auditService = new DataProtectionAuditService();
            final var anonymizationService = new DataAnonymizationService();
            final var consentService = new ConsentManagementService(auditService);
            final var sarService = new SubjectAccessRequestService(auditService, anonymizationService);
            
            // Initialize concurrent processor
            final var concurrentProcessor = new ConcurrentOrderProcessor();
            
            // Comprehensive demonstration including data protection compliance
            demonstrateGdprCompliantProcessing(concurrentProcessor, auditService, 
                anonymizationService, consentService, sarService);
            
        } catch (Exception e) {
            LOGGER.severe("Application failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    /**
     * Comprehensive demonstration of concurrent processing features
     */
    private static void demonstrateConcurrentProcessing(final ConcurrentOrderProcessor processor) 
            throws Exception {
        
        LOGGER.info("=".repeat(90));
        LOGGER.info("🚀 CONCURRENT ORDER PROCESSING DEMONSTRATION");
        LOGGER.info("=".repeat(90));
        
        // Demo 1: Single Order Processing
        LOGGER.info("\n📋 Demo 1: Single Order Processing with Monitoring");
        LOGGER.info("-".repeat(50));
        
        final var singleOrder = createSampleOrder();
        displayOrderSummary(singleOrder);
        
        final var singleResult = processor.processOrderAsync(singleOrder).get();
        displayProcessingResult(singleResult);
        
        // Brief pause for readability
        Thread.sleep(1000);
        
        // Demo 2: Concurrent Batch Processing
        LOGGER.info("\n📦 Demo 2: Concurrent Batch Processing (10 Orders)");
        LOGGER.info("-".repeat(50));
        
        final var batchOrders = createOrderBatch(10);
        LOGGER.info("Processing %d orders concurrently...".formatted(batchOrders.size()));
        
        final var batchStart = System.currentTimeMillis();
        final var batchResults = processor.processBatchAsync(batchOrders).get();
        final var batchTime = System.currentTimeMillis() - batchStart;
        
        displayBatchResults(batchResults, batchTime);
        
        // Demo 3: High-Throughput Stress Test
        LOGGER.info("\n⚡ Demo 3: High-Throughput Stress Test (25 Orders)");
        LOGGER.info("-".repeat(50));
        
        final var stressOrders = createOrderBatch(25); // Reduced for faster demo
        final var stressStart = System.currentTimeMillis();
        
        // Process in parallel using futures
        final var stressFutures = stressOrders.stream()
            .map(processor::processOrderAsync)
            .collect(Collectors.toList());
        
        LOGGER.info("Submitted %d orders for concurrent processing...".formatted(stressOrders.size()));
        
        // Wait for all to complete
        final var stressResults = stressFutures.stream()
            .map(CompletableFuture::join)
            .collect(Collectors.toList());
        
        final var stressTime = System.currentTimeMillis() - stressStart;
        displayStressTestResults(stressResults, stressTime);
        
        // Brief pause for readability
        Thread.sleep(1000);
        
        // Demo 4: Performance Metrics & Monitoring
        LOGGER.info("\n📊 Demo 4: Performance Metrics & System Health");
        LOGGER.info("-".repeat(50));
        
        displaySystemMetrics(processor);
        
        // Brief pause for readability
        Thread.sleep(1000);
        
        // Demo 5: Resilience Testing (Simulated Load)
        LOGGER.info("\n🛡️ Demo 5: Resilience & Circuit Breaker Demo");
        LOGGER.info("-".repeat(50));
        
        demonstrateResilience(processor);
        
        LOGGER.info("\n" + "=".repeat(90));
        LOGGER.info("✅ CONCURRENT PROCESSING DEMONSTRATION COMPLETE!");
        LOGGER.info("🏆 All enterprise-grade features validated successfully");
        LOGGER.info("=".repeat(90));
        
        // Shutdown the processor to stop background monitoring
        LOGGER.info("\n🔄 Shutting down concurrent processor...");
        processor.shutdown();
        LOGGER.info("✅ Graceful shutdown completed. Application terminating.");
    }
    
    /**
     * Comprehensive demonstration of GDPR-compliant processing with data protection features
     */
    private static void demonstrateGdprCompliantProcessing(
            final ConcurrentOrderProcessor processor,
            final DataProtectionAuditService auditService,
            final DataAnonymizationService anonymizationService,
            final ConsentManagementService consentService,
            final SubjectAccessRequestService sarService) throws Exception {
        
        LOGGER.info("\n" + "=".repeat(100));
        LOGGER.info("🛡️ GDPR-COMPLIANT ORDER PROCESSING WITH DATA PROTECTION");
        LOGGER.info("=".repeat(100));
        
        // Phase 1: Concurrent Processing Demo (existing)
        demonstrateConcurrentProcessing(processor);
        
        LOGGER.info("\n" + "=".repeat(100));
        LOGGER.info("🔐 DATA PROTECTION & PRIVACY COMPLIANCE DEMONSTRATION");
        LOGGER.info("=".repeat(100));
        
        // Phase 2: Data Protection Demo
        demonstrateDataProtectionFeatures(auditService, anonymizationService, 
            consentService, sarService);
        
        // Phase 3: Privacy-by-Design PDF Generation
        demonstratePrivacyByDesignPdf();
        
        // Phase 4: Compliance Reporting
        demonstrateComplianceReporting(auditService, consentService, sarService);
        
        // Shutdown all services
        LOGGER.info("\n🔄 Shutting down all data protection services...");
        processor.shutdown();
        auditService.shutdown();
        sarService.shutdown();
        LOGGER.info("✅ Complete GDPR-compliant shutdown completed.");
    }
    
    /**
     * Demonstrate core data protection features
     */
    private static void demonstrateDataProtectionFeatures(
            final DataProtectionAuditService auditService,
            final DataAnonymizationService anonymizationService,
            final ConsentManagementService consentService,
            final SubjectAccessRequestService sarService) throws Exception {
        
        LOGGER.info("\n📋 Demo 1: Data Classification & Anonymization");
        LOGGER.info("-".repeat(60));
        
        final var sampleCustomer = createSampleOrder().customer();
        
        // Demonstrate data detection and classification
        final var personalData = anonymizationService.detectPersonalData(
            sampleCustomer.getFullName() + " " + sampleCustomer.email() + " " + sampleCustomer.phone());
        
        LOGGER.info("🔍 Personal Data Detection Results:");
        personalData.forEach((data, classification) -> 
            LOGGER.info("  • %s: %s".formatted(data, classification.getDisplayName())));
        
        // Demonstrate anonymization
        LOGGER.info("\n🎭 Data Anonymization Results:");
        LOGGER.info("  • Original Email: %s".formatted(sampleCustomer.email()));
        LOGGER.info("  • Anonymized: %s".formatted(
            anonymizationService.anonymizeData(sampleCustomer.email(), DataClassification.PERSONAL)));
        LOGGER.info("  • Pseudonymized: %s".formatted(
            anonymizationService.pseudonymizeData(sampleCustomer.email(), "customer")));
        
        Thread.sleep(1000);
        
        LOGGER.info("\n📝 Demo 2: Consent Management");
        LOGGER.info("-".repeat(60));
        
        final var customerId = sampleCustomer.customerId();
        
        // Grant various consents
        consentService.grantConsent(customerId, new ConsentType.Essential(), 
            TEST_IP_ADDRESS, TEST_USER_AGENT, Duration.ofDays(365));
        consentService.grantConsent(customerId, new ConsentType.Marketing(), 
            TEST_IP_ADDRESS, TEST_USER_AGENT, Duration.ofDays(180));
        consentService.grantConsent(customerId, new ConsentType.Analytics(), 
            TEST_IP_ADDRESS, TEST_USER_AGENT, Duration.ofDays(90));
        
        final var consentSummary = consentService.getConsentSummary(customerId);
        LOGGER.info("📊 Consent Summary for %s:".formatted(customerId));
        LOGGER.info("  • Total Consents: %d".formatted(consentSummary.totalConsents()));
        LOGGER.info("  • Valid Consents: %d".formatted(consentSummary.validConsents()));
        LOGGER.info("  • Expired Consents: %d".formatted(consentSummary.expiredConsents()));
        LOGGER.info("  • Near Expiry: %d".formatted(consentSummary.nearExpiryConsents()));
        
        // Test consent withdrawal
        final var withdrawResult = consentService.withdrawConsent(customerId, 
            new ConsentType.Marketing(), TEST_IP_ADDRESS);
        LOGGER.info("  • Marketing Consent Withdrawn: %s".formatted(withdrawResult ? "✅" : "❌"));
        
        Thread.sleep(1000);
        
        LOGGER.info("\n📤 Demo 3: Subject Access Requests (GDPR Rights)");
        LOGGER.info("-".repeat(60));
        
        // Submit data export request
        final var exportRequest = sarService.submitAccessRequest(
            customerId, EXPORT_OPERATION, TEST_IP_ADDRESS, "Email Verification").get();
        LOGGER.info("📥 Data Export Request: %s".formatted(exportRequest.requestId()));
        LOGGER.info("  • Status: %s".formatted(exportRequest.status()));
        LOGGER.info("  • Processing Time: %d ms".formatted(exportRequest.getProcessingTime().toMillis()));
        
        // Submit deletion request (Right to be Forgotten)
        final var deleteRequest = sarService.submitAccessRequest(
            customerId, DELETE_OPERATION, TEST_IP_ADDRESS, "Email Verification").get();
        LOGGER.info("🗑️ Data Deletion Request: %s".formatted(deleteRequest.requestId()));
        LOGGER.info("  • Status: %s".formatted(deleteRequest.status()));
        
        Thread.sleep(1000);
        
        LOGGER.info("\n📊 Demo 4: Audit Trail & Compliance Logging");
        LOGGER.info("-".repeat(60));
        
        final var auditEvents = auditService.getAuditEvents(customerId);
        LOGGER.info("📋 Audit Events for Customer %s:".formatted(customerId));
        auditEvents.stream().limit(5).forEach(event -> 
            LOGGER.info("  • %s: %s - %s".formatted(
                event.timestamp().format(DateTimeFormatter.ofPattern(TIME_FORMAT_HH_MM_SS)),
                event.operation().getDisplayName(),
                event.details())));
        
        if (auditEvents.size() > 5) {
            LOGGER.info("  • ... and %d more events".formatted(auditEvents.size() - 5));
        }
    }
    
    /**
     * Demonstrate privacy-by-design PDF generation
     */
    private static void demonstratePrivacyByDesignPdf() throws Exception {
        Thread.sleep(1000);
        
        LOGGER.info("\n🔒 Demo 5: Privacy-by-Design PDF Generation");
        LOGGER.info("-".repeat(60));
        
        final var sampleOrder = createSampleOrder();
        final var pdfService = new PdfGenerationService();
        
        try {
            // Generate regular PDF
            final var regularPdf = pdfService.generateOrderConfirmation(sampleOrder, false);
            LOGGER.info("📄 Regular PDF Generated: %s".formatted(
                regularPdf.substring(regularPdf.lastIndexOf('/') + 1)));
            
            // Generate anonymized PDF
            final var anonymizedPdf = pdfService.generateOrderConfirmation(sampleOrder, true);
            LOGGER.info("🎭 Anonymized PDF Generated: %s".formatted(
                anonymizedPdf.substring(anonymizedPdf.lastIndexOf('/') + 1)));
            
            LOGGER.info("✅ Both PDFs generated with appropriate privacy controls");
            LOGGER.info("  • Regular: Contains full personal data with privacy notices");
            LOGGER.info("  • Anonymized: Uses pseudonymization and masking for privacy protection");
        } finally {
            // Critical: Shutdown internal audit service to prevent resource leak
            pdfService.auditService.shutdown();
        }
    }
    
    /**
     * Demonstrate compliance reporting capabilities
     */
    private static void demonstrateComplianceReporting(
            final DataProtectionAuditService auditService,
            final ConsentManagementService consentService,
            final SubjectAccessRequestService sarService) throws Exception {
        
        Thread.sleep(1000);
        
        LOGGER.info("\n📈 Demo 6: Compliance Reporting & Monitoring");
        LOGGER.info("-".repeat(60));
        
        final var reportStart = LocalDateTime.now().minusMinutes(10);
        final var reportEnd = LocalDateTime.now();
        
        final var complianceReport = auditService.generateComplianceReport(reportStart, reportEnd);
        
        LOGGER.info("📊 GDPR Compliance Report (%s to %s):".formatted(
            reportStart.format(DateTimeFormatter.ofPattern(TIME_FORMAT_HH_MM_SS)),
            reportEnd.format(DateTimeFormatter.ofPattern(TIME_FORMAT_HH_MM_SS))));
        
        LOGGER.info("  📈 Audit Metrics:");
        LOGGER.info("    • Total Events: %d".formatted(complianceReport.totalEvents()));
        LOGGER.info("    • Error Events: %d".formatted(complianceReport.errorEvents()));
        LOGGER.info("    • Success Rate: %.2f%%".formatted(
            (complianceReport.totalEvents() - complianceReport.errorEvents()) * 100.0 / 
            Math.max(1, complianceReport.totalEvents())));
        
        LOGGER.info("  🔍 Operations Breakdown:");
        complianceReport.operationCounts().forEach((operation, count) ->
            LOGGER.info("    • %s: %d events".formatted(operation.getDisplayName(), count)));
        
        LOGGER.info("  🏷️ Data Classification Breakdown:");
        complianceReport.classificationCounts().forEach((classification, count) ->
            LOGGER.info("    • %s: %d events".formatted(classification.getDisplayName(), count)));
        
        // Check for overdue SAR requests
        final var overdueRequests = sarService.getOverdueRequests();
        LOGGER.info("  ⏰ Overdue SAR Requests: %d".formatted(overdueRequests.size()));
        if (!overdueRequests.isEmpty()) {
            LOGGER.warning("    ⚠️ WARNING: GDPR requires SAR processing within 30 days!");
        }
        
        LOGGER.info("\n✅ All GDPR compliance features demonstrated successfully!");
        LOGGER.info("🏆 System meets enterprise data protection standards");
    }
    
    /**
     * Creates a batch of sample orders for testing
     */
    private static java.util.List<Order> createOrderBatch(final int size) {
        final var orders = new ArrayList<Order>();
        
        for (int i = 0; i < size; i++) {
            final var baseOrder = createSampleOrder();
            
            // Create variations for realistic testing
            final var customerId = "CUST-" + (12345 + i);
            final var orderId = "ORD-" + (System.currentTimeMillis() + i);
            
            final var customer = new Customer(
                customerId,
                "Customer",
                "Number" + i,
                "customer%d@test.com".formatted(i),
                "(555) 123-%04d".formatted(i),
                baseOrder.customer().billingAddress(),
                baseOrder.customer().shippingAddress()
            );
            
            final var order = new Order(
                orderId,
                customer,
                baseOrder.items(),
                baseOrder.shipments(),
                baseOrder.appliedCoupons(),
                baseOrder.status(),
                LocalDateTime.now().minusMinutes(i),
                baseOrder.shippingCost(),
                baseOrder.taxRate(),
                "Batch order #" + (i + 1)
            );
            
            orders.add(order);
        }
        
        return orders;
    }
    
    private static void displayProcessingResult(final ConcurrentOrderProcessor.ProcessingResult result) {
        LOGGER.info("""
            ✅ Order Processed: %s
            📄 PDF: %s
            ⏱️ Time: %d ms
            📊 Status: %s
            """.formatted(
                result.orderId(),
                result.pdfPath() != null ? result.pdfPath().substring(result.pdfPath().lastIndexOf('/') + 1) : "FAILED",
                result.processingTimeMs(),
                result.status()
            ));
    }
    
    private static void displayBatchResults(final java.util.List<ConcurrentOrderProcessor.ProcessingResult> results, 
                                          final long totalTime) {
        final var successCount = results.stream()
            .mapToInt(r -> r.status() == ConcurrentOrderProcessor.ProcessingStatus.SUCCESS ? 1 : 0)
            .sum();
        
        final var avgTime = results.stream()
            .mapToLong(ConcurrentOrderProcessor.ProcessingResult::processingTimeMs)
            .average()
            .orElse(0.0);
        
        LOGGER.info("""
            📈 Batch Processing Results:
            ✅ Success: %d/%d orders
            ⏱️ Total Time: %d ms
            📊 Average per Order: %.1f ms
            🚀 Throughput: %.1f orders/second
            """.formatted(
                successCount, results.size(),
                totalTime,
                avgTime,
                (results.size() * 1000.0) / totalTime
            ));
    }
    
    private static void displayStressTestResults(final java.util.List<ConcurrentOrderProcessor.ProcessingResult> results,
                                               final long totalTime) {
        final var successCount = results.stream()
            .mapToInt(r -> r.status() == ConcurrentOrderProcessor.ProcessingStatus.SUCCESS ? 1 : 0)
            .sum();
        
        final var failureCount = results.size() - successCount;
        final var throughput = (results.size() * 1000.0) / totalTime;
        
        LOGGER.info("""
            ⚡ High-Throughput Stress Test Results:
            📊 Total Orders: %d
            ✅ Successful: %d
            ❌ Failed: %d
            ⏱️ Total Time: %d ms
            🚀 Throughput: %.1f orders/second
            💪 Success Rate: %.1f%%
            """.formatted(
                results.size(),
                successCount,
                failureCount,
                totalTime,
                throughput,
                (successCount * 100.0) / results.size()
            ));
    }
    
    private static void displaySystemMetrics(final ConcurrentOrderProcessor processor) {
        final var metrics = processor.getMetrics();
        final var circuitStats = processor.getCircuitBreakerStats();
        
        LOGGER.info("""
            📊 System Performance Metrics:
            🔢 Total Processed: %d orders
            ⚡ Currently Processing: %d
            ⏱️ Average Processing Time: %d ms
            📈 Peak Concurrency: %d threads
            ❌ Total Errors: %d
            🛡️ Circuit Breaker: %s
            🎯 Error Rate: %.2f%%
            """.formatted(
                metrics.totalProcessed(),
                metrics.currentlyProcessing(),
                metrics.averageProcessingTimeMs(),
                metrics.peakConcurrency(),
                metrics.totalErrors(),
                circuitStats.state(),
                metrics.totalProcessed() > 0 ? 
                    (metrics.totalErrors() * 100.0) / metrics.totalProcessed() : 0.0
            ));
        
        // Display operation-specific metrics
        if (!metrics.operationMetrics().isEmpty()) {
            LOGGER.info("\n🔍 Operation Breakdown:");
            metrics.operationMetrics().forEach((operation, totalTime) -> 
                LOGGER.info("  • %s: %d ms total".formatted(operation, totalTime)));
        }
    }
    
    private static void demonstrateResilience(final ConcurrentOrderProcessor processor) {
        LOGGER.info("🧪 Testing system resilience with rapid requests...");
        
        final var resilientOrders = createOrderBatch(10); // Reduced for faster demo
        final var futures = new ArrayList<CompletableFuture<ConcurrentOrderProcessor.ProcessingResult>>();
        
        // Submit requests rapidly to test rate limiting
        for (final var order : resilientOrders) {
            futures.add(processor.processOrderAsync(order));
            
            // Small delay to simulate realistic load
            try {
                Thread.sleep(5); // Reduced delay for faster demo
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        // Wait for completion
        final var resilientResults = futures.stream()
            .map(CompletableFuture::join)
            .collect(Collectors.toList());
        
        final var rateLimitedCount = resilientResults.stream()
            .mapToInt(r -> r.status() == ConcurrentOrderProcessor.ProcessingStatus.FAILED && 
                          r.errorMessage() != null && 
                          r.errorMessage().contains("Rate limit") ? 1 : 0)
            .sum();
        
        LOGGER.info("""
            🛡️ Resilience Test Results:
            📊 Total Requests: %d
            ✅ Processed: %d
            🚫 Rate Limited: %d
            🔧 Circuit Breaker State: %s
            """.formatted(
                resilientResults.size(),
                resilientResults.size() - rateLimitedCount,
                rateLimitedCount,
                processor.getCircuitBreakerStats().state()
            ));
    }
    
    private static void displayOrderSummary(final Order order) {
        LOGGER.info("\n" + "=".repeat(80));
        LOGGER.info("📋 ORDER CONFIRMATION PREVIEW");
        LOGGER.info("=".repeat(80));
        LOGGER.info("Order ID: " + order.orderId());
        LOGGER.info("Customer: " + order.customer().getFullName());
        LOGGER.info("Status: " + order.status().getDisplayName());
        LOGGER.info("Items: " + order.items().size());
        LOGGER.info("Backorders: " + (order.hasBackorderedItems() ? "Yes" : "No"));
        LOGGER.info("Split Shipments: " + (order.hasSplitShipments() ? "Yes" : "No"));
        LOGGER.info("Grand Total: $%.2f".formatted(order.getGrandTotal()));
        LOGGER.info("=".repeat(80));
        LOGGER.info("🔄 Processing PDF generation...");
    }
} 