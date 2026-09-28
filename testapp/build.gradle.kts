/*
 * Copyright 2026 Google LLC
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
  id("com.adarshr.test-logger") version "4.0.0"
  id("org.jetbrains.kotlin.jvm") version "2.2.0"
}

repositories {
  val repoDir =
    findProperty("KeyAttestationMavenRepo") as? String
      ?: layout.projectDirectory.dir("../build/keyattestation_m2repo").asFile.absolutePath
  maven { url = uri(repoDir) }
  mavenCentral()
  google()
}

val keyAttestationVersion =
  (findProperty("keyAttestationReleaseVersion") as? String)?.removePrefix("v") ?: "+"

dependencies {
  implementation("com.android.keyattestation:keyattestation:$keyAttestationVersion")

  testImplementation(kotlin("test"))
  testImplementation("com.google.truth:truth:1.4.4")

  // Required to run JUnit 4 tests.
  testRuntimeOnly("org.junit.vintage:junit-vintage-engine")
}

java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }

tasks {
  test {
    workingDir = layout.projectDirectory.dir("..").asFile
    useJUnitPlatform()
    testLogging { exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
  }
}
