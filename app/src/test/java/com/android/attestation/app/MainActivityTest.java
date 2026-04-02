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
package com.android.attestation.app;

import static com.google.common.truth.Truth.assertThat;

import android.view.View;
import android.widget.Button;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.android.controller.ActivityController;

/** Minimal tests for {@link MainActivity}. */
@RunWith(AndroidJUnit4.class)
public class MainActivityTest {

  private MainActivity activity;
  private Button attestButton;

  @Before
  public void setUp() {
    ActivityController<MainActivity> controller = Robolectric.buildActivity(MainActivity.class);
    controller.get().setTheme(R.style.AppTheme);
    activity = controller.setup().get();
    attestButton = activity.findViewById(R.id.attest_button);
  }

  @Test
  public void activityShouldStart() {
    assertThat(activity).isNotNull();
  }

  @Test
  public void attestButtonShouldBeVisible() {
    assertThat(attestButton).isNotNull();
    assertThat(attestButton.getVisibility()).isEqualTo(View.VISIBLE);
  }
}
