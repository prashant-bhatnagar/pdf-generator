plugins {
    application
    java
}

group = "com.example"
version = "1.0.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(24)
    }
}

application {
    mainClass = "com.example.OrderConfirmationPdfGenerator"
}

repositories {
    mavenCentral()
}

dependencies {
    // Modern PDF generation (iText 8.x for high performance)
    implementation("com.itextpdf:itext-core:8.0.5")
    implementation("com.itextpdf:bouncy-castle-adapter:8.0.5")
    
    // Security - Bouncy Castle for encryption
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    
    // Performance monitoring and caching
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.8")
    
    // JSON processing for configuration
    implementation("com.fasterxml.jackson.core:jackson-core:2.17.2")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    
    // Testing with modern JUnit
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    testImplementation("org.mockito:mockito-core:5.7.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.7.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.release = 24
    options.compilerArgs.addAll(listOf(
        "--enable-preview",
        "-Xlint:all",
        "-Xlint:-serial",
        "-Xlint:-preview"
    ))
}

tasks.withType<JavaExec> {
    jvmArgs("--enable-preview")
}

tasks.jar {
    manifest {
        attributes(
            "Main-Class" to "com.example.OrderConfirmationPdfGenerator",
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version
        )
    }
    
    // Create a fat JAR with all dependencies
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
} 