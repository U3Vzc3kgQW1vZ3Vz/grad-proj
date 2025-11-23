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

tasks.withType<Test> {
    enabled = false // Disable all Test tasks
}

tasks.named("compileTestJava") {
    enabled = false // Disable compileTestJava task
}

// Existing 'tasks.test' block can remain, but its 'enabled = false' on tasks.withType<Test> will take precedence.
// If it's necessary to keep this block, its effects will be nullified by disabling the task.
tasks.test {
    // Excludes test suites from the default test task
    // to avoid running some tests multiple times.
    filter {
        excludeTestsMatching("*TestSuite")
    }
}

task("testTaieTestSuite", type = Test::class) {
    enabled = false // Disable this specific Test task
}

// Automatically agree the Gradle ToS when running gradle with '--scan' option
extensions.findByName("buildScan")?.withGroovyBuilder {
    setProperty("termsOfServiceUrl", "https://gradle.com/terms-of-service")
    setProperty("termsOfServiceAgree", "yes")
}

