import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("java")
    id("org.jetbrains.kotlin.jvm") version "2.0.21"
    id("org.jetbrains.intellij") version "1.17.4"
}

group = "com.reconpro"
version = "0.1.0"

repositories {
    mavenCentral()
}

intellij {
    version.set("2024.1")
    type.set("IC")
    plugins.set(listOf())
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks {
    patchPluginXml {
        sinceBuild.set("241")
        untilBuild.set("243.*")
    }

    register<Exec>("reconproSmoke") {
        // Runs the same argv list ReconProRunner.buildCommand() produces.
        description = "Executes the CLI contract (doctor --json) the plugin would run."
        commandLine("python3", "-m", "reconpro.cli", "doctor", "--json")
    }
}
