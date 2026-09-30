plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    toolchain { languageVersion.set(JavaLanguageVersion.of(17)) }
}

dependencies {
    api(project(":pairing"))
    api(project(":core:serialization"))
    implementation(project(":core:logging"))
    implementation(libs.bouncycastle.prov)
    implementation(libs.bouncycastle.tls)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}

tasks.test {
    testLogging { events("passed", "failed", "skipped") }
}
