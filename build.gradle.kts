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

import org.gradle.api.tasks.compile.JavaCompile
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
  id("com.adarshr.test-logger") version "4.0.0"
  id("org.jetbrains.kotlin.jvm") version "2.2.0"
  `maven-publish`
}

repositories {
  mavenCentral()
  google()
}

dependencies {
  implementation("androidx.annotation:annotation:1.9.1")
  implementation("co.nstant.in:cbor:0.9")
  implementation("com.google.code.gson:gson:2.11.0")
  implementation("com.google.errorprone:error_prone_annotations:2.41.0")
  implementation("com.google.protobuf:protobuf-javalite:4.28.3")
  implementation("com.google.protobuf:protobuf-kotlin-lite:4.28.3")
  implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
  implementation("org.jetbrains.kotlin:kotlin-stdlib:2.2.0")
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-guava:1.10.2")
  implementation("com.google.guava:guava:33.5.0-jre")

  testImplementation(kotlin("test"))
  testImplementation("com.google.testparameterinjector:test-parameter-injector:1.18")
  testImplementation("com.google.truth:truth:1.4.4")

  // Required to run JUnit 4 tests.
  testRuntimeOnly("org.junit.vintage:junit-vintage-engine")
}

java {
  toolchain { languageVersion = JavaLanguageVersion.of(21) }
  withSourcesJar()
}

kotlin {
  compilerOptions {
    jvmTarget = JvmTarget.JVM_11
    freeCompilerArgs.add("-Xjdk-release=11")
  }
}

tasks {
  withType<JavaCompile>().configureEach { options.release.set(11) }

  test {
    useJUnitPlatform()
    testLogging { exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
  }

  compileTestKotlin { compilerOptions { javaParameters = true } }
}

val generatedSourcesDir = layout.buildDirectory.dir("generated")

val googleTrustAnchors by tasks.registering {
  val jsonFile = file("roots.json")
  val json = jsonFile.readText()
  val generatedFile = generatedSourcesDir.get().file("main/kotlin/GoogleTrustAnchors.kt")

  inputs.files(jsonFile)
  outputs.file(generatedFile)

  doLast {
    generatedFile
      .getAsFile()
      .writeText(
        """
        package com.android.keyattestation.verifier

        import com.android.keyattestation.verifier.asX509Certificate

        import com.google.gson.Gson
        import java.security.cert.TrustAnchor

        object GoogleTrustAnchors : () -> Set<TrustAnchor> {
          const val JSON = ""${'"'}
            $json
            ""${'"'}

          override operator fun invoke(): Set<TrustAnchor> {
            return Gson()
              .fromJson(JSON, Array<String>::class.java)
              .map { TrustAnchor(it.asX509Certificate(), null) }
              .toSet()
          }
        }
        """
      )
  }
}

val generateSources by tasks.registering {
  outputs.dir(generatedSourcesDir)
  dependsOn(tasks.named("googleTrustAnchors"))
}

sourceSets { main { kotlin.srcDir(generateSources) } }

tasks.named("compileKotlin").configure { dependsOn("generateSources") }

publishing {
  publications {
    create<MavenPublication>("keyattestation") {
      from(components["java"])
      groupId = "com.android.keyattestation"
      artifactId = "keyattestation"
      version =
        (findProperty("keyAttestationReleaseVersion") as? String)?.removePrefix("v")
          ?: "0.1-SNAPSHOT"
    }
  }

  repositories {
    maven {
      name = "localDir"
      val repoDir =
        findProperty("KeyAttestationMavenRepo") as? String
          ?: rootProject.layout.buildDirectory
            .dir("keyattestation_m2repo")
            .get()
            .asFile
            .absolutePath
      url = uri(repoDir)
    }
  }
}
