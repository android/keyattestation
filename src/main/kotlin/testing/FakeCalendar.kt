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

package com.android.keyattestation.verifier.testing

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.Date

class FakeCalendar(val today: LocalDate = LocalDate.of(2024, 10, 20)) {
  fun today(): Date = today.toDate()

  fun now(): Instant = today.atStartOfDay(ZoneId.of("UTC")).toInstant()

  fun yesterday(): Date = today.minusDays(1).toDate()

  fun tomorrow(): Date = today.plusDays(1).toDate()

  private fun Instant.toDate() = Date.from(this)

  private fun LocalDate.toDate() = this.atStartOfDay(ZoneId.of("UTC")).toInstant().toDate()

  companion object {
    @JvmField val DEFAULT = FakeCalendar()
  }
}
