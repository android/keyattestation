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
