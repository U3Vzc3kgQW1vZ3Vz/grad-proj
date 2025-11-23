// rootProject.name = "Tai-e" // Mismatch between project name and folder name may cause Intellij error

include(
    ":", // root project
    "docs",
)

// Defines the classpath to be used by the 'runMain' task in build.gradle.kts
gradle.extra["classPath"] = listOf<String>(
    // Add paths to directories or jars here
)