
import com.diffplug.gradle.spotless.SpotlessApply
import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

buildscript {
    repositories {
        mavenCentral()
    }
}

plugins {
    java
    signing
    `maven-publish`
    alias(libs.plugins.kotlin)
    alias(libs.plugins.spotless)
    alias(libs.plugins.license.report)
    alias(libs.plugins.versions)
}

val descriptions: Map<String, String> = mapOf(
    "idscp2-api" to "IDSCP2 Protocol API",
    "idscp2-core" to "IDSCP2 Protocol Implementation",
    "idscp2-app-layer" to "IDSCP2 Application Layer Implementation",
    "idscp2-daps-aisec" to "IDSCP2 AISEC DAPS Driver",
    "camel-idscp2" to "Camel IDSCP2 Component Implementation",
    "infomodel" to "Legacy IAIS Infomodel Classes"
)

allprojects {
    group = "de.fhg.aisec.ids"

    repositories {
        mavenCentral()
        // Legacy IAIS Infomodel artifact repo
        maven("https://gitlab.cc-asp.fraunhofer.de/api/v4/projects/55371/packages/maven")
    }

    val versionRegex = ".*(rc|beta|alpha)-?[0-9]*$".toRegex(RegexOption.IGNORE_CASE)

    tasks.withType<DependencyUpdatesTask> {
        rejectVersionIf {
            // Reject release candidates and betas and pin Apache Camel to 3.18 LTS version
            versionRegex.matches(candidate.version)
                || (candidate.group in setOf("org.apache.camel", "org.apache.camel.springboot")
                && !candidate.version.startsWith("3.18"))
                || candidate.group == "com.google.protobuf" && !candidate.version.startsWith("3.")
        }
    }
}

// Create and register ExecutionService which enforces serial execution of assigned tasks
abstract class SerialExecutionService : BuildService<BuildServiceParameters.None>
val serialExecutionService =
    gradle.sharedServices.registerIfAbsent("serialExecution", SerialExecutionService::class.java) {
        this.maxParallelUsages.set(1)
    }

val spotlessApplyAll: Task by tasks.creating

subprojects {
    apply(plugin = "java")
    apply(plugin = "kotlin")

    tasks.withType<Javadoc> {
        exclude("de/fhg/aisec/ids/idscp2/messages/**", "de/fhg/aisec/ids/idscp2/applayer/messages/**")
    }

    java {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
        withSourcesJar()
        withJavadocJar()
    }

    tasks.test {
        exclude("**/*IT.*")
    }

    val integrationTest = tasks.register<Test>("integrationTest") {
        include("**/*IT.*")
        systemProperty("project.version", "$project.version")
    }

    tasks.withType<Test> {
        testLogging {
            events("failed")
            exceptionFormat = TestExceptionFormat.FULL
        }
    }

    tasks.check {
        dependsOn(integrationTest)
    }

    // define some Bill of Materials (BOM) for all subprojects
    dependencies {
        // Logging API
        api(rootProject.libs.slf4j.api)
        dependencies {
            val versions = rootProject.libs.versions
            // Some versions are downgraded for unknown reasons, fix this here
            val groupPins = mapOf(
                "org.jetbrains.kotlin" to mapOf(
                    "*" to versions.kotlin.get()
                ),
                "com.google.guava" to mapOf(
                    "guava" to versions.guava.get()
                )
            )
            // We need to explicitly specify the kotlin version for all kotlin dependencies,
            // because otherwise something (maybe a plugin) downgrades the kotlin version,
            // which produces errors in the kotlin compiler. This is really nasty.
            configurations.all {
                resolutionStrategy.eachDependency {
                    groupPins[requested.group]?.let { pins ->
                        pins["*"]?.let {
                            // Pin all names when asterisk is set
                            useVersion(it)
                        } ?: pins[requested.name]?.let { pin ->
                            // Pin only for specific names given in map
                            useVersion(pin)
                        }
                    }
                }
            }
        }
    }

    tasks.withType<KotlinCompile> {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
        // options.compilerArgs.add("-Xlint:unchecked")
        // options.isDeprecation = true
    }

    tasks.jar {
        manifest {
            attributes(
                "Bundle-Vendor" to "Fraunhofer AISEC",
                "-noee" to true
            )
        }
    }

    apply(plugin = "maven-publish")
    apply(plugin = "signing")

    if (project.name in descriptions.keys) {
        publishing {
            publications {
                register("idscp2Library", MavenPublication::class) {
                    from(components["java"])
                    pom {
                        name.set(project.name)
                        description.set(descriptions[project.name])
                        url.set("https://github.com/industrial-data-space/idscp2-jvm")
                        licenses {
                            license {
                                name.set("The Apache License, Version 2.0")
                                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                            }
                        }
                        developers {
                            developer {
                                name.set("Michael Lux")
                                email.set("michael.lux@aisec.fraunhofer.de")
                                organization.set("Fraunhofer AISEC")
                                organizationUrl.set("aisec.fraunhofer.de")
                            }
                        }
                        scm {
                            connection.set("scm:git:git://github.com:industrial-data-space/idscp2-jvm.git")
                            developerConnection.set("scm:git:ssh://github.com:industrial-data-space/idscp2-jvm.git")
                            url.set("https://github.com/industrial-data-space/idscp2-jvm")
                        }
                    }
                }
            }

            repositories {
                if (project.hasProperty("publishLocal")) {
                    mavenLocal()
                } else {
                    maven {
                        url = uri(
                            if (version.toString().endsWith("SNAPSHOT")) {
                                "https://oss.sonatype.org/content/repositories/snapshots"
                            } else {
                                "https://oss.sonatype.org/service/local/staging/deploy/maven2"
                            }
                        )

                        credentials {
                            username = project.findProperty("deployUsername") as? String
                            password = project.findProperty("deployPassword") as? String
                        }
                    }

                    // Prevent parallel publishing
                    tasks.withType<PublishToMavenRepository> {
                        usesService(serialExecutionService)
                    }
                }
            }
        }

        if (!project.hasProperty("publishLocal")) {
            signing {
                useGpgCmd()
                sign(publishing.publications.getByName("idscp2Library"))
            }
        }
    }

    apply(plugin = "com.github.jk1.dependency-license-report")

    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("src/*/kotlin/**/*.kt")
            ktlint(libs.versions.ktlint.get()).editorConfigOverride(mapOf(
                "ktlint_code_style" to "intellij_idea"
            ))
            licenseHeader(
                """/*-
 * ========================LICENSE_START=================================
 * ${project.name}
 * %%
 * Copyright (C) ${"$"}YEAR Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */"""
            ).yearSeparator(" - ")
        }
    }

    tasks.withType<SpotlessApply> {
        spotlessApplyAll.dependsOn(this.path)
    }
}
