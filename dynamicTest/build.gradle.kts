plugins {
    java
    application
}

repositories {
    mavenCentral()
}

dependencies {
    // Load JARs from java-benchmarks/JDV/target/
    implementation(fileTree("../java-benchmarks/JDV/target") {
        include("**/*.jar")
    })

    // Additional dependencies that may not be in JDV/target
    implementation("javax.servlet:javax.servlet-api:4.0.1")

    // jsoup for Vaadin 7.7.14 compatibility
    implementation("org.jsoup:jsoup:1.8.3")

    // Missing transitive dependency for commons-beanutils
    implementation("commons-collections:commons-collections:3.2.2")
    implementation("commons-logging:commons-logging:1.2")
}

sourceSets {
    main {
        java {
            // Assuming user might have put files directly in src/ or src/main/java
            // We'll include both common locations just in case
            srcDirs("src", "src/main/java")
        }
    }
}

application {
    // Default main class, can be overridden
    mainClass.set("GroovyFullChainExploit")
}

// Register run tasks for each exploit class
tasks.register<JavaExec>("runC3P0") {
    group = "exploits"
    description = "Run C3P0ClassLoaderExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("C3P0ClassLoaderExploit")
}

tasks.register<JavaExec>("runCommonsBeanutils") {
    group = "exploits"
    description = "Run CommonsBeanutilsJNDIExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("CommonsBeanutilsJNDIExploit")
}

tasks.register<JavaExec>("runFileUploadSSRF") {
    group = "exploits"
    description = "Run FileUploadSSRFExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("FileUploadSSRFExploit")
    systemProperty("org.apache.commons.collections.enableUnsafeSerialization", "true")
}

tasks.register<JavaExec>("runGroovyCustomSink") {
    group = "exploits"
    description = "Run GroovyCustomSinkExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("GroovyCustomSinkExploit")
}

tasks.register<JavaExec>("runGroovyExec") {
    group = "exploits"
    description = "Run GroovyExecExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("GroovyExecExploit")
}

tasks.register<JavaExec>("runGroovyFileDelete") {
    group = "exploits"
    description = "Run GroovyFileDeleteExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("GroovyFileDeleteExploit")
}

tasks.register<JavaExec>("runGroovyFullChain") {
    group = "exploits"
    description = "Run GroovyFullChainExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("GroovyFullChainExploit")
}

tasks.register<JavaExec>("runVaadin") {
    group = "exploits"
    description = "Run VaadinReflectionExploit"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("VaadinReflectionExploit")
}

tasks.register<JavaExec>("runDeserialize") {
    group = "exploits"
    description = "Run DeserializePayload to test gadget chain deserialization"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("DeserializePayload")

    // Pass command line arguments for payload file
    if (project.hasProperty("payload")) {
        args = listOf(project.property("payload") as String)
    }
    // Otherwise no args means it will use default "jndi-gadget-payload.ser"
}

tasks.register<JavaExec>("testSSRFChain") {
    group = "exploits"
    description = "Generate and immediately test SSRF payload (avoids serialVersionUID issues)"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("FileUploadSSRFExploit")

    // Pass target URL if specified
    if (project.hasProperty("target")) {
        args = listOf(project.property("target") as String)
    }
}

tasks.withType<JavaExec> {
    // Enable access to internal modules for the exploit POCs only on JDK 9+
    if (JavaVersion.current().isJava9Compatible) {
        jvmArgs(
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/java.util=ALL-UNNAMED",
            "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
            "--add-opens=java.base/java.io=ALL-UNNAMED",
            "--add-opens=java.base/java.net=ALL-UNNAMED",
            "--add-opens=java.management/javax.management=ALL-UNNAMED",
            "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
            "--add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED"
        )
    }
}
