# Order Confirmation PDF Generator

A modern Java 24 application that generates professional PDF documents for order confirmations using Gradle build system.

## Features

This project demonstrates modern Java 24 features and best practices:

- **Records**: Immutable data structures for Order, Customer, Address, and OrderItem
- **Sealed Classes**: Type-safe order status hierarchy
- **Text Blocks**: Multi-line string literals for readable content
- **Pattern Matching**: Modern switch expressions and pattern matching
- **Local Variable Type Inference**: Using `var` for cleaner code
- **Modern Collections API**: Streams and functional programming patterns

## Project Structure

```
order-confirmation-pdf-generator/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── com/
│   │   │       └── example/
│   │   │           └── OrderConfirmationPdfGenerator.java
│   │   └── resources/
│   └── test/
│       └── java/
│           └── com/
│               └── example/
├── gradle/
│   └── wrapper/
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
├── gradlew.bat
└── README.md
```

## Prerequisites

- **JDK 24**: This project requires Java Development Kit 24 or later
- **Windows**: The batch files are configured for Windows environments

## Getting Started

### 1. Verify Java Installation

Make sure you have JDK 24 installed:

```batch
java -version
```

### 2. Build the Project

Use the Gradle wrapper to build the project:

```batch
.\gradlew.bat build
```

### 3. Run the Application

Execute the main class to generate a sample PDF:

```batch
.\gradlew.bat run
```

This will:
- Create an `output` directory
- Generate a sample order confirmation PDF
- Display success message with the generated filename

### 4. Build Executable JAR

Create a standalone executable JAR with all dependencies:

```batch
.\gradlew.bat jar
```

The JAR will be created in `build/libs/` directory.

## Code Structure

The entire application logic is contained in a single Java file: `OrderConfirmationPdfGenerator.java`

### Key Components

1. **Sealed Interface `OrderStatus`**: Type-safe order status hierarchy
2. **Records**:
   - `OrderItem`: Represents individual items with validation
   - `Customer`: Customer information
   - `Address`: Address details with formatted output
   - `Order`: Complete order information with calculations

3. **PDF Generation**: Comprehensive PDF creation with:
   - Professional header and footer
   - Customer information section
   - Detailed items table
   - Order summary with tax and shipping calculations

## Configuration

### Gradle Build Configuration

- **Java Toolchain**: Configured for JDK 24
- **Application Plugin**: Enables `run` task
- **Fat JAR**: Includes all dependencies in the output JAR
- **JDK 24 Features**: Enabled preview features and modern compiler flags

### Dependencies

- **iText PDF**: For PDF generation capabilities
- **JUnit 5**: For testing framework

## Usage Examples

### Basic Usage

```java
var generator = new OrderConfirmationPdfGenerator();
var order = createSampleOrder();
String pdfFilename = generator.generatePdf(order);
```

### Creating Custom Orders

```java
var address = new Address("123 Main St", "City", "State", "12345", "Country");
var customer = new Customer("John Doe", "john@example.com", "555-1234", address);

var items = List.of(
    new OrderItem("Product 1", 2, new BigDecimal("29.99"), "Description"),
    new OrderItem("Product 2", 1, new BigDecimal("49.99"), "Description")
);

var order = new Order(
    "ORD-123",
    customer,
    items,
    new Confirmed(),
    LocalDateTime.now(),
    new BigDecimal("5.99"),  // shipping
    new BigDecimal("0.08")   // 8% tax
);
```

## Build Tasks

- `.\gradlew.bat clean` - Clean build artifacts
- `.\gradlew.bat build` - Compile and test the application
- `.\gradlew.bat run` - Execute the main class
- `.\gradlew.bat test` - Run unit tests
- `.\gradlew.bat jar` - Create executable JAR

## Output

Generated PDFs include:
- Professional order confirmation header
- Customer information section
- Detailed items table with quantities and pricing
- Tax and shipping calculations
- Order total and summary
- Contact information footer

## Customization

The single Java file can be easily modified to:
- Add new order status types (extend the sealed interface)
- Modify PDF layout and styling
- Add additional customer or order fields
- Implement different calculation methods
- Add validation rules

## Modern Java Features Used

- **Records** (JDK 14+): Immutable data carriers
- **Sealed Classes** (JDK 17+): Restricted inheritance hierarchies
- **Text Blocks** (JDK 15+): Multi-line string literals
- **Pattern Matching** (JDK 21+): Enhanced switch expressions
- **Local Variable Type Inference** (JDK 10+): `var` keyword
- **Streams API**: Functional programming patterns

## License

This project is provided as-is for educational and demonstration purposes. 