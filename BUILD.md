# Building

## What you need

- JDK 17
- Android SDK with platform 35 and build-tools 35.0.0
- Nothing else. No Python, no NDK, no native toolchain.

## Build

```sh
./gradlew test              # all unit tests, on the JVM, no emulator
./gradlew :app:lintDebug    # Android lint
./gradlew :app:assembleDebug
```

The debug APK lands in `app/build/outputs/apk/debug/app-debug.apk` and is
signed with a locally generated debug key, so it installs by sideloading.

```sh
./gradlew :app:assembleRelease
```

The release APK is **unsigned**. To get an installable one, add your own
keystore and a signing config; a release APK signed with the debug key would
be installable by anyone who wanted to replace it, which is not a trade worth
making.

## Memory

The default Gradle heap in `gradle.properties` is deliberately modest so the
build completes on a small machine. On a normal desktop, raising
`org.gradle.jvmargs` and re-enabling `org.gradle.parallel` makes it much
faster.

## Installing

```sh
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

On Android TV, sideload with the TV's own file manager or `adb connect`.
