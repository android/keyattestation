/*
 * Copyright 2025 Google LLC
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

import android.app.Activity;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.security.KeyStoreException;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

/**
 * Utility class providing helper methods to verify Android device states, build configurations, and
 * user profile environments.
 */
public final class AttestationUtils {

  public static void showAlertDialog(
      Activity activity, String title, String message, String buttonText) {
    new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setMessage(message)
        .setPositiveButton(buttonText, null)
        .setCancelable(false)
        .show();
  }

  /**
   * Returns {@code true} if the network is likely available, or if its status cannot be determined.
   *
   * <p>This method fails open: it returns {@code false} only when it's definitively known that the
   * network is unavailable. If there's insufficient information or an exception occurs during the
   * check, it defaults to returning {@code true}.
   */
  public static boolean isNetworkAvailable(Context context) {
    try {
      ConnectivityManager cm =
          (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

      if (cm == null) {
        return true;
      }

      Network activeNetwork = cm.getActiveNetwork();
      if (activeNetwork == null) {
        return false;
      }

      NetworkCapabilities capabilities = cm.getNetworkCapabilities(activeNetwork);
      return capabilities == null
          || capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);

    } catch (RuntimeException e) {
      return true;
    }
  }

  public static boolean isCannotAttestIdsError(Exception e) {
    int errorCode = getKeystoreErrorCode(e);

    return errorCode == KeyStoreException.ERROR_ID_ATTESTATION_FAILURE;
  }

  public static boolean isNetworkError(Exception e) {
    int errorCode = getKeystoreErrorCode(e);

    return errorCode == KeyStoreException.RETRY_WHEN_CONNECTIVITY_AVAILABLE
        || e instanceof UnknownHostException
        || e instanceof SocketTimeoutException
        || e instanceof ConnectException;
  }

  private static int getKeystoreErrorCode(Exception e) {
    Throwable throwable = e instanceof KeyStoreException ? e : e.getCause();
    if (throwable instanceof KeyStoreException kse) {
      return kse.getNumericErrorCode();
    }
    return Integer.MAX_VALUE;
  }

  private AttestationUtils() {}
}
