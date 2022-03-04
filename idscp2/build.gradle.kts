import com.google.protobuf.gradle.protobuf
import org.gradle.plugins.ide.idea.model.IdeaModel

@Suppress("UNCHECKED_CAST")
val libraryVersions = rootProject.extra.get("libraryVersions") as Map<String, String>

version = libraryVersions["idscp2"] ?: error("IDSCP2 version not specified")

apply(plugin = "java")
apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

val generatedProtoBaseDir = "$projectDir/generated"

protobuf {
    generatedFilesBaseDir = generatedProtoBaseDir
}

tasks.named("clean") {
    doLast {
        delete(generatedProtoBaseDir)
    }
}

configure<IdeaModel> {
    module {
        // mark as generated sources for IDEA
        generatedSourceDirs.add(File("$generatedProtoBaseDir/main/java"))
    }
}

val api by configurations
val testImplementation by configurations

dependencies {
    implementation("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", libraryVersions["kotlinxCoroutines"])

    implementation("org.bouncycastle", "bcprov-jdk15on", libraryVersions["bouncycastle"])

    implementation("com.google.protobuf", "protobuf-java", libraryVersions["protobuf"])

    implementation("io.jsonwebtoken", "jjwt-impl", libraryVersions["jsonwebtoken"])
    // Important, since io.jsonwebtoken:jjwt-jackson references an outdated version with critical CVEs
    implementation("com.fasterxml.jackson.core", "jackson-databind", libraryVersions["jackson"])
    implementation("io.jsonwebtoken", "jjwt-jackson", libraryVersions["jsonwebtoken"])
    implementation("io.jsonwebtoken", "jjwt-api", libraryVersions["jsonwebtoken"])
    implementation("org.bitbucket.b_c", "jose4j", libraryVersions["jose4j"])
    implementation("io.ktor", "ktor-client-core", libraryVersions["ktor"])
    implementation("io.ktor", "ktor-client-java", libraryVersions["ktor"])
    implementation("io.ktor", "ktor-client-content-negotiation", libraryVersions["ktor"])
    implementation("io.ktor", "ktor-serialization-jackson", libraryVersions["ktor"])

    testImplementation("org.awaitility", "awaitility-kotlin", libraryVersions["awaitility"])
    testImplementation("junit", "junit", libraryVersions["junit4"])
    testImplementation("org.mockito", "mockito-core", libraryVersions["mockito"])
}

tasks.named("spotlessKotlin") {
    dependsOn(tasks.named("generateProto"))
    dependsOn(tasks.named("generateTestProto"))
}
