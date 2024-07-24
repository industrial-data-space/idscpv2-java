version = libs.versions.idscp2.get()

val api by configurations
val testImplementation by configurations

dependencies {
    api(project(":idscp2-api"))

    implementation(libs.bouncycastle)
    implementation(libs.protobuf)

    testImplementation(libs.awaitility)
    testImplementation(libs.junit)
    testImplementation(libs.mockito)
    testImplementation(libs.slf4j.impl)
}
