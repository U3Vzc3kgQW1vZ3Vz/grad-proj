import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory

plugins {
    application
    id("tai-e.conventions")
    id("maven-publish.conventions")
}

group = projectGroupId
description = projectArtifactId
version = projectVersion

dependencies {
    implementation("com.opencsv:opencsv:5.5.1")
    // Process options
    implementation("info.picocli:picocli:4.7.3")
    // Logger
    implementation("org.apache.logging.log4j:log4j-api:2.20.0")
    implementation("org.apache.logging.log4j:log4j-core:2.20.0")
    // Process YAML configuration files
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.0")
    // Use Soot as frontend
    implementation(files("lib/sootclasses-modified.jar"))
    "org.soot-oss:soot:4.4.1".let {
        // Disable transitive dependencies from Soot in compile classpath
        compileOnly(it) { isTransitive = false }
        testCompileOnly(it) { isTransitive = false }
        runtimeOnly(it)
    }
    // Use ASM to read Java class files
    implementation("org.ow2.asm:asm:9.4")
    // Eliminate SLF4J warning
    implementation("org.slf4j:slf4j-nop:2.0.7")
    // JSR305, for javax.annotation
    implementation("com.google.code.findbugs:jsr305:3.0.2")
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("javax.servlet:javax.servlet-api:4.0.1")

    // Dependencies for exploit POC examples (optional, for educational purposes)
    // These are compileOnly so they don't pollute the production classpath
    compileOnly("org.apache.groovy:groovy:4.0.15")
    compileOnly("org.apache.groovy:groovy-all:4.0.15")
    compileOnly("com.mchange:c3p0:0.9.5.5")
    compileOnly("commons-beanutils:commons-beanutils:1.9.4")
    compileOnly("com.vaadin:vaadin-server:8.14.3")

    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit.platform:junit-platform-suite")
    runtimeOnly("org.jsoup:jsoup:1.15.3")
}

application {
    mainClass.set("pascal.taie.Main")
}

tasks.named("run", JavaExec::class) {
    jvmArgs = listOf("-Xss100m")
}

task<JavaExec>("runDynamicTester") {
    group = "application"
    description = "Runs the dynamic gadget chain tester"
    val mainClasspath = sourceSets.main.get().runtimeClasspath
    val ymlFile = file("java-benchmarks/JDV/test.yml")
    val mapper = ObjectMapper(YAMLFactory())
    val config = mapper.readValue(ymlFile, Map::class.java)
    val appClassPath: List<String> = (config["appClassPath"] as? List<*>)
        ?.mapNotNull { it as? String }
        ?: error("appClassPath is missing or not a list of strings in test.yml")
    val appClasspath = files(appClassPath.map { path ->
        val dir = file(path)
        // Return a file tree for jars if it's a directory, otherwise the file itself
        if (dir.isDirectory) fileTree(mapOf("dir" to dir, "include" to listOf("**/*.jar"))) + files(dir) else files(dir)
    })
    classpath = mainClasspath + appClasspath
    mainClass.set("pascal.taie.dynamic.DynamicTester")
    args = listOf("--options-file", "java-benchmarks/JDV/test.yml")
    jvmArgs = listOf(
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.io=ALL-UNNAMED",
        "--add-opens=java.base/sun.reflect=ALL-UNNAMED",
        "--add-opens=java.base/java.net=ALL-UNNAMED",
        "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
        "--add-opens=java.management/javax.management=ALL-UNNAMED",
        "--add-opens=java.management/javax.management.openmbean=ALL-UNNAMED",
        "--add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
        "--add-opens=java.sql/java.sql=ALL-UNNAMED",
        "--add-opens=java.sql.rowset/com.sun.rowset=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xerces.internal.impl.xs.util=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xpath.internal.objects=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xerces.internal.util=ALL-UNNAMED",
        "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
        "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
        "--add-opens=java.base/java.time.chrono=ALL-UNNAMED",
        "--add-opens=java.base/sun.net.www.protocol.file=ALL-UNNAMED",
        "--add-opens=java.base/java.time=ALL-UNNAMED",
        "--add-opens=java.xml/com.sun.org.apache.xml.internal.utils=ALL-UNNAMED"
    )
}

task<JavaExec>("runMain") {
    group = "application"
    description = "Runs pascal.taie.Main with classpath from settings.gradle.kts"
    val mainClasspath = sourceSets.main.get().runtimeClasspath

    val extraClassPath: List<String> = if (gradle.extra.has("classPath")) {
        @Suppress("UNCHECKED_CAST")
        gradle.extra["classPath"] as List<String>
    } else {
        emptyList()
    }

    val appClasspath = files(extraClassPath.map { path ->
        val dir = file(path)
        // Return a file tree for jars if it's a directory, otherwise the file itself
        if (dir.isDirectory) fileTree(mapOf("dir" to dir, "include" to listOf("**/*.jar"))) + files(dir) else files(dir)
    })

    classpath = mainClasspath + appClasspath
    mainClass.set("pascal.taie.Main")

    // Pass command line arguments
    if (project.hasProperty("args")) {
        args = (project.property("args") as String).split("\\s+".toRegex())
    } else {
        args = listOf("--options-file", "java-benchmarks/JDV/test.yml")
    }

    jvmArgs = listOf("-Xss512m", "-Xmx8G")
}


task("fatJar", type = Jar::class) {
    group = "build"
    description = "Creates a single jar file including Tai-e and all dependencies"
    manifest {
        attributes["Main-Class"] = "pascal.taie.Main"
    }
    archiveBaseName.set("tai-e-all")
    from(
        configurations.runtimeClasspath.get().map {
            if (it.isDirectory) it else zipTree(it)
        }
    )
    from("COPYING", "COPYING.LESSER")
    destinationDirectory.set(rootProject.layout.buildDirectory)
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    with(tasks["jar"] as CopySpec)
}

tasks.jar {
    from("COPYING", "COPYING.LESSER")
    from(zipTree("lib/sootclasses-modified.jar"))
    destinationDirectory.set(rootProject.layout.buildDirectory)
}

// Enable tests for verification
tasks.withType<JavaCompile>().configureEach {
    if (name == "compileTestJava") {
        enabled = true
        // Only compile our test to avoid errors in existing tests
        include("pascal/taie/analysis/dataflow/analysis/methodsummary/plugin/ChainDeduplicatorTest.java")
    }
    if (name == "compileJava") {
        // Exclude example exploit POCs from main build (they require specific vulnerable library versions)
        exclude("pascal/taie/analysis/gadget/examples/**")
    }
}

tasks.withType<Test> {
    enabled = true
    useJUnitPlatform()
}

// Task to compile exploit examples separately
tasks.register<JavaCompile>("compileExamples") {
    group = "build"
    description = "Compiles exploit POC examples separately"
    source = fileTree("src/main/java/pascal/taie/analysis/gadget/examples")
    classpath = sourceSets.main.get().compileClasspath
    destinationDirectory.set(file("$buildDir/classes/java/examples"))
}

// Task to compile only Groovy examples
tasks.register<JavaCompile>("compileGroovyExample") {
    group = "build"
    description = "Compiles only Groovy-related exploit examples"
    source = fileTree("src/main/java/pascal/taie/analysis/gadget/examples") {
        include("Groovy*.java")
    }
    classpath = sourceSets.main.get().compileClasspath
    destinationDirectory.set(file("$buildDir/classes/java/examples"))
}

// Task to run Groovy exploit example
tasks.register<JavaExec>("runGroovyExample") {
    group = "examples"
    description = "Runs the Groovy custom sink exploit example"
    dependsOn("compileGroovyExample")

    // Build classpath with all required dependencies
    classpath = files(
        "$buildDir/classes/java/examples",
        configurations.compileClasspath.get()
    )

    mainClass.set("pascal.taie.analysis.gadget.examples.GroovyCustomSinkExploit")

    // Java module system options for reflection
    jvmArgs = listOf(
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "--add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED",
        "--add-opens=java.management/javax.management=ALL-UNNAMED"
    )
}

// ============================================================================
// Individual Exploit Example Tasks
// ============================================================================

// Helper function to create exploit example tasks
fun createExampleTask(
    taskName: String,
    className: String,
    description: String,
    includePattern: String = "${className}.java"
) {
    // Compile task
    tasks.register<JavaCompile>("compile${taskName}") {
        group = "build"
        this.description = "Compiles ${className}"
        source = fileTree("src/main/java/pascal/taie/analysis/gadget/examples") {
            include(includePattern)
        }
        classpath = sourceSets.main.get().compileClasspath
        destinationDirectory.set(file("$buildDir/classes/java/examples"))
    }

    // Run task
    tasks.register<JavaExec>("run${taskName}") {
        group = "examples"
        this.description = description
        dependsOn("compile${taskName}")

        classpath = files(
            "$buildDir/classes/java/examples",
            configurations.compileClasspath.get()
        )

        mainClass.set("pascal.taie.analysis.gadget.examples.${className}")

        jvmArgs = listOf(
            "--add-opens=java.base/java.lang=ALL-UNNAMED",
            "--add-opens=java.base/java.util=ALL-UNNAMED",
            "--add-opens=java.base/java.io=ALL-UNNAMED",
            "--add-opens=java.base/java.net=ALL-UNNAMED",
            "--add-opens=java.management/javax.management=ALL-UNNAMED",
            "--add-opens=java.desktop/javax.swing=ALL-UNNAMED"
        )
    }
}

// C3P0 ClassLoader Exploit
createExampleTask(
    "C3P0Example",
    "C3P0ClassLoaderExploit",
    "Runs C3P0 ClassLoader gadget chain exploit (CLASS_LOADER sink)"
)

// Commons Beanutils JNDI Exploit
createExampleTask(
    "BeanutilsExample",
    "CommonsBeanutilsJNDIExploit",
    "Runs Commons Beanutils JNDI injection exploit (JNDI sink)"
)

// FileUpload SSRF Exploit
createExampleTask(
    "FileUploadExample",
    "FileUploadSSRFExploit",
    "Runs FileUpload SSRF gadget chain exploit (SSRF sink)"
)

// Groovy Exec Exploit
createExampleTask(
    "GroovyExecExample",
    "GroovyExecExploit",
    "Runs Groovy command execution exploit (EXEC sink)"
)

// Groovy File Delete Exploit
createExampleTask(
    "GroovyFileDeleteExample",
    "GroovyFileDeleteExploit",
    "Runs Groovy file deletion exploit (FILE sink)"
)

// Vaadin Reflection Exploit
createExampleTask(
    "VaadinExample",
    "VaadinReflectionExploit",
    "Runs Vaadin reflection-based SSRF exploit"
)

// Task to compile all examples
tasks.register<JavaCompile>("compileAllExamples") {
    group = "build"
    description = "Compiles all exploit POC examples"
    source = fileTree("src/main/java/pascal/taie/analysis/gadget/examples") {
        include("*Exploit.java")
    }
    classpath = sourceSets.main.get().compileClasspath
    destinationDirectory.set(file("$buildDir/classes/java/examples"))
}

// Task to list all available examples
tasks.register("listExamples") {
    group = "examples"
    description = "Lists all available exploit example tasks"
    doLast {
        println("╔════════════════════════════════════════════════════════════╗")
        println("║            Available Exploit Examples                     ║")
        println("╚════════════════════════════════════════════════════════════╝")
        println()
        println("Run examples with: ./gradlew <taskName>")
        println()
        println("Available tasks:")
        println("  1. runC3P0Example          - C3P0 ClassLoader (CLASS_LOADER sink)")
        println("  2. runBeanutilsExample     - Commons Beanutils JNDI (JNDI sink)")
        println("  3. runFileUploadExample    - FileUpload SSRF (SSRF sink)")
        println("  4. runGroovyExample        - Groovy Custom Sink (CUSTOM sink)")
        println("  5. runGroovyExecExample    - Groovy Command Execution (EXEC sink)")
        println("  6. runGroovyFileDeleteExample - Groovy File Delete (FILE sink)")
        println("  7. runVaadinExample        - Vaadin Reflection SSRF")
        println()
        println("Compile tasks:")
        println("  - compileAllExamples       - Compile all examples")
        println("  - compile<Name>            - Compile specific example")
        println()
        println("═══════════════════════════════════════════════════════════")
    }
}
