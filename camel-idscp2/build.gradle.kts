version = libs.versions.idscp2.get()

dependencies {
    api(project(":idscp2-app-layer"))
    api(project(":idscp2-daps-aisec"))
    api(libs.infomodel)

    implementation(project(":idscp2-core"))
    implementation(libs.camel.core)
    implementation(libs.protobuf)
    implementation(libs.guava) {
        isTransitive = false // Avoid pulling in of checker framework and other annotation stuff
    }

    testImplementation(libs.junit)
    testImplementation(libs.camel.test)
    testImplementation(libs.mockito)
}
