/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    kotlin("jvm") version "2.0.20"
}

group = "com.google"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.google.protobuf:protobuf-javalite:4.28.3")
    implementation("com.squareup.moshi:moshi-kotlin:1.15.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    implementation("com.google.guava:guava:33.3.1-android")

    testImplementation(kotlin("test"))
    testImplementation("com.google.truth:truth:1.4.4")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}