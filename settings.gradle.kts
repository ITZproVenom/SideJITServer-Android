pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "SideJITServer-Android"

include(":app")
include(":core:logging")
include(":core:crypto")
include(":core:serialization")
include(":core:net")
include(":core:mdns")
include(":pairing")
include(":coredevice")
include(":developer")
include(":jit")
include(":server")
include(":platform")
