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
import android.content.res.ColorStateList;
import android.os.Handler;
import android.os.Looper;
import android.support.v7.app.ActionBar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.StringRes;
import androidx.core.content.ContextCompat;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.common.io.BaseEncoding;
import com.google.protobuf.ByteString;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.Locale;

/**
 * Utility class for updating the UI of the Attestation Verifier app.
 *
 * <p>This class provides methods for updating the UI based on the verification result, such as
 * updating the summary card, bootloader banner, and parameter details.
 */
public final class AttestationUiManager {
  private static final String TAG = "AttestationUiManager";
  private final Activity activity;
  private final Handler handler = new Handler(Looper.getMainLooper());

  public static final int EIGHT_DIGIT_PATCH_LEVEL = 8;
  public static final int SIX_DIGIT_PATCH_LEVEL = 6;

  public AttestationUiManager(Activity activity) {
    this.activity = activity;
  }

  /** Enum representing the different parameter names displayed in the UI. */
  public enum AttestationParameter {
    VERIFICATION_RESULT(R.string.label_verification_result),
    ATTESTATION_CHALLENGE(R.string.label_attestation_challenge),
    ATTESTATION_SECURITY_LEVEL(R.string.label_attestation_security_level),
    KEYMASTER_VERSION(R.string.label_keymaster_version),
    KEYMASTER_SECURITY_LEVEL(R.string.label_keymaster_security_level),
    CREATION_DATE(R.string.label_creation_date),
    APPLICATION_ID(R.string.label_id_device),
    ATTESTATION_PURPOSES(R.string.label_attestation_purposes),
    ATTESTATION_ALGORITHMS(R.string.label_attestation_algorithms),
    KEY_SIZE(R.string.label_key_size),
    DIGESTS(R.string.label_digests),
    EC_CURVE(R.string.label_ec_curve),
    ATTESTATION_ORIGIN(R.string.label_origin),
    ROOT_OF_TRUST(R.string.label_root_of_trust),
    ROT_STATE(R.string.label_rot_state),
    ROT_LOCKED(R.string.label_rot_locked),
    NO_AUTH_REQUIRED(R.string.label_no_auth_required),
    ACTIVE_DATE(R.string.label_active_date),
    ORIGINATION_EXPIRE_DATE(R.string.label_origination_expire_date),
    USAGE_EXPIRE_DATE(R.string.label_usage_expire_date),
    USER_AUTH_TYPE(R.string.label_user_auth_type),
    AUTH_TIMEOUT(R.string.label_auth_timeout),
    TRUSTED_USER_PRESENCE_REQUIRED(R.string.label_presence_required),
    UNLOCKED_DEVICE_REQUIRED(R.string.label_unlocked_required),
    ATTESTATION_OS_VERSION(R.string.label_os_version),
    ATTESTATION_OS_PATCH(R.string.label_os_patch),
    VENDOR_PATCH_LEVEL(R.string.label_vendor_patch),
    BOOT_PATCH_LEVEL(R.string.label_boot_patch),
    ATTESTATION_ID_BRAND(R.string.label_id_brand),
    ATTESTATION_ID_MODEL(R.string.label_id_model),
    ATTESTATION_ID_SERIAL(R.string.label_id_serial),
    ATTESTATION_ID_IMEI(R.string.label_id_imei),
    RSA_PUBLIC_EXPONENT(R.string.label_rsa_exponent),
    ATTESTATION_MODULE_HASH(R.string.label_module_hash),
    ERROR(R.string.label_error);

    private final int labelResId;

    AttestationParameter(@StringRes int labelResId) {
      this.labelResId = labelResId;
    }

    @StringRes
    public int getLabelResId() {
      return labelResId;
    }
  }

  /**
   * Initializes the Activity's Action Bar with the application icon and title.
   *
   * <p>This method should be called during {@code Activity.onCreate}, immediately after {@code
   * setContentView}. It is safe to call this method multiple times; subsequent calls will simply
   * re-apply the icon and display configurations to the existing Action Bar.
   */
  public void setupActionBar() {
    if (activity instanceof AppCompatActivity appCompatActivity) {
      ActionBar actionBar = appCompatActivity.getSupportActionBar();
      if (actionBar != null) {
        actionBar.setTitle(R.string.app_name);
        actionBar.setDisplayShowHomeEnabled(true);
        actionBar.setIcon(activity.getApplicationInfo().icon);
      }
    }
  }

  public void updateSummaryStatus(boolean isVerified) {
    handler.post(
        () -> {
          View summaryCard = activity.findViewById(R.id.summary_card);
          if (summaryCard == null) {
            return;
          }

          summaryCard.setVisibility(View.VISIBLE);
          TextView summaryTitle = activity.findViewById(R.id.summary_title);
          TextView summarySubtitle = activity.findViewById(R.id.summary_subtitle);

          if (isVerified) {
            summaryTitle.setText(R.string.summary_title_verified);
            summaryTitle.setTextColor(ContextCompat.getColor(activity, R.color.brand_success));
            summaryTitle.setCompoundDrawablesWithIntrinsicBounds(
                0, R.drawable.ic_check_circle, 0, 0);
            summaryTitle.setCompoundDrawableTintList(
                ColorStateList.valueOf(ContextCompat.getColor(activity, R.color.brand_success)));

            summarySubtitle.setText(R.string.summary_subtitle_verified);
          } else {
            summaryTitle.setText(R.string.summary_title_unverified);
            summaryTitle.setTextColor(ContextCompat.getColor(activity, R.color.brand_grey));
            summaryTitle.setCompoundDrawablesWithIntrinsicBounds(0, R.drawable.ic_warning, 0, 0);
            summaryTitle.setCompoundDrawableTintList(
                ColorStateList.valueOf(ContextCompat.getColor(activity, R.color.brand_grey)));

            summarySubtitle.setText(R.string.summary_subtitle_unverified);
          }
        });
  }

  public String getParameterDescription(
      AttestationParameter parameter, EnforcementType enforcement) {
    String description = "";
    String example = "";
    switch (parameter) {
      case VERIFICATION_RESULT -> {
        description = activity.getString(R.string.desc_verification_result);
        example = activity.getString(R.string.ex_verification_result);
      }
      case ATTESTATION_CHALLENGE -> {
        description = activity.getString(R.string.desc_attestation_challenge);
        example = activity.getString(R.string.ex_attestation_challenge);
      }
      case ATTESTATION_SECURITY_LEVEL -> {
        description = activity.getString(R.string.desc_attestation_security_level);
        example = activity.getString(R.string.ex_attestation_security_level);
      }
      case KEYMASTER_VERSION -> {
        description = activity.getString(R.string.desc_keymaster_version);
        example = activity.getString(R.string.ex_keymaster_version);
      }
      case KEYMASTER_SECURITY_LEVEL -> {
        description = activity.getString(R.string.desc_keymaster_security_level);
        example = activity.getString(R.string.ex_keymaster_security_level);
      }
      case CREATION_DATE -> {
        description = activity.getString(R.string.desc_creation_date);
        example = activity.getString(R.string.ex_creation_date);
      }
      case APPLICATION_ID -> {
        description = activity.getString(R.string.desc_application_id);
        example = activity.getString(R.string.ex_application_id);
      }
      case ATTESTATION_PURPOSES -> {
        description = activity.getString(R.string.desc_attestation_purposes);
        example = activity.getString(R.string.ex_attestation_purposes);
      }
      case ATTESTATION_ALGORITHMS -> {
        description = activity.getString(R.string.desc_attestation_algorithms);
        example = activity.getString(R.string.ex_attestation_algorithms);
      }
      case KEY_SIZE -> {
        description = activity.getString(R.string.desc_key_size);
        example = activity.getString(R.string.ex_key_size);
      }
      case DIGESTS -> {
        description = activity.getString(R.string.desc_digests);
        example = activity.getString(R.string.ex_digests);
      }
      case EC_CURVE -> {
        description = activity.getString(R.string.desc_ec_curve);
        example = activity.getString(R.string.ex_ec_curve);
      }
      case ATTESTATION_ORIGIN -> {
        description = activity.getString(R.string.desc_attestation_origin);
        example = activity.getString(R.string.ex_attestation_origin);
      }
      case ROOT_OF_TRUST -> {
        description = activity.getString(R.string.desc_root_of_trust);
        example = activity.getString(R.string.ex_root_of_trust);
      }
      case ROT_STATE -> {
        description = activity.getString(R.string.desc_rot_state);
        example = activity.getString(R.string.ex_rot_state);
      }
      case ROT_LOCKED -> {
        description = activity.getString(R.string.desc_rot_locked);
        example = activity.getString(R.string.ex_rot_locked);
      }
      case NO_AUTH_REQUIRED -> {
        description = activity.getString(R.string.desc_no_auth_required);
        example = activity.getString(R.string.ex_no_auth_required);
      }
      case ACTIVE_DATE -> description = activity.getString(R.string.desc_active_date);
      case ORIGINATION_EXPIRE_DATE ->
          description = activity.getString(R.string.desc_origination_expire_date);
      case USAGE_EXPIRE_DATE -> description = activity.getString(R.string.desc_usage_expire_date);
      case USER_AUTH_TYPE -> {
        description = activity.getString(R.string.desc_user_auth_type);
        example = activity.getString(R.string.ex_user_auth_type);
      }
      case AUTH_TIMEOUT -> description = activity.getString(R.string.desc_auth_timeout);
      case TRUSTED_USER_PRESENCE_REQUIRED ->
          description = activity.getString(R.string.desc_trusted_user_presence_required);
      case UNLOCKED_DEVICE_REQUIRED ->
          description = activity.getString(R.string.desc_unlocked_device_required);
      case ATTESTATION_OS_VERSION -> {
        description = activity.getString(R.string.desc_attestation_os_version);
        example = activity.getString(R.string.ex_attestation_os_version);
      }
      case ATTESTATION_OS_PATCH -> {
        description = activity.getString(R.string.desc_attestation_os_patch);
        example = activity.getString(R.string.ex_attestation_os_patch);
      }
      case VENDOR_PATCH_LEVEL -> {
        description = activity.getString(R.string.desc_vendor_patch_level);
        example = activity.getString(R.string.ex_vendor_patch_level);
      }
      case BOOT_PATCH_LEVEL -> {
        description = activity.getString(R.string.desc_boot_patch_level);
        example = activity.getString(R.string.ex_boot_patch_level);
      }
      case ATTESTATION_ID_BRAND -> {
        description = activity.getString(R.string.desc_attestation_id_brand);
        example = activity.getString(R.string.ex_attestation_id_brand);
      }
      case ATTESTATION_ID_MODEL -> {
        description = activity.getString(R.string.desc_attestation_id_model);
        example = activity.getString(R.string.ex_attestation_id_model);
      }
      case ATTESTATION_ID_SERIAL ->
          description = activity.getString(R.string.desc_attestation_id_serial);
      case ATTESTATION_ID_IMEI ->
          description = activity.getString(R.string.desc_attestation_id_imei);
      case RSA_PUBLIC_EXPONENT -> {
        description = activity.getString(R.string.desc_rsa_public_exponent);
        example = activity.getString(R.string.ex_rsa_public_exponent);
      }
      case ATTESTATION_MODULE_HASH ->
          description = activity.getString(R.string.desc_attestation_module_hash);
      default -> description = activity.getString(R.string.desc_default);
    }

    StringBuilder popupText = new StringBuilder(description);

    if (example != null && !example.isEmpty()) {
      popupText
          .append("\n\n")
          .append(activity.getString(R.string.label_example_prefix))
          .append(" ")
          .append(example);
    }

    if (enforcement != null && enforcement != EnforcementType.NONE) {
      String footer =
          switch (enforcement) {
            case TEE -> activity.getString(R.string.enforced_by_tee);
            case SOFTWARE -> activity.getString(R.string.enforced_by_sw);
            case HARDWARE -> activity.getString(R.string.enforced_by_hw);
            default -> "";
          };
      popupText.append("\n\n").append(footer);
    }

    return popupText.toString();
  }

  public void showAboutDialog() {
    new MaterialAlertDialogBuilder(activity)
        .setTitle(R.string.about_key_attestation_title)
        .setMessage(activity.getString(R.string.about_key_attestation_dialog_message))
        .setPositiveButton(R.string.ok, null)
        .show();
  }

  public void showParameterDetailDialog(String title, String message) {
    new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setMessage(message)
        .setPositiveButton(R.string.ok, null)
        .show();
  }

  public void updateBootloaderBanner(boolean isLocked) {
    handler.post(
        () -> {
          MaterialCardView banner = activity.findViewById(R.id.bootloader_banner);
          TextView statusText = activity.findViewById(R.id.bootloader_text);
          ImageView icon = activity.findViewById(R.id.bootloader_icon);

          if (banner == null) {
            return;
          }
          banner.setVisibility(View.VISIBLE);

          if (isLocked) {
            statusText.setText(R.string.bootloader_locked);
            banner.setCardBackgroundColor(
                ContextCompat.getColor(activity, R.color.brand_blue_light));
            statusText.setTextColor(ContextCompat.getColor(activity, R.color.brand_blue_dark));
            icon.setImageResource(android.R.drawable.ic_lock_lock);
            icon.setImageTintList(
                ColorStateList.valueOf(ContextCompat.getColor(activity, R.color.brand_blue_dark)));
          } else {
            statusText.setText(R.string.bootloader_unlocked);
            banner.setCardBackgroundColor(
                ContextCompat.getColor(activity, R.color.brand_warning_light));
            statusText.setTextColor(ContextCompat.getColor(activity, R.color.brand_brown_dark));
            icon.setImageResource(android.R.drawable.ic_lock_idle_lock);
            icon.setImageTintList(
                ColorStateList.valueOf(ContextCompat.getColor(activity, R.color.brand_brown_dark)));
          }
        });
  }

  public String formatDate(BigInteger timestamp) {
    if (timestamp == null || timestamp.equals(BigInteger.ZERO)) {
      return activity.getString(R.string.not_applicable);
    }
    try {
      Instant instant = Instant.ofEpochMilli(timestamp.longValue());

      DateTimeFormatter formatter =
          DateTimeFormatter.ofPattern("MMMM dd, yyyy hh:mm a").withZone(ZoneId.systemDefault());

      return formatter.format(instant);
    } catch (RuntimeException e) {
      return String.valueOf(timestamp);
    }
  }

  public String formatPatchLevel(Object value) {
    if (value == null) {
      return activity.getString(R.string.not_applicable);
    }
    String patchStr = String.valueOf(value);

    try {
      if (patchStr.length() == EIGHT_DIGIT_PATCH_LEVEL) {
        LocalDate date = LocalDate.parse(patchStr, DateTimeFormatter.ofPattern("yyyyMMdd"));
        return date.format(
            DateTimeFormatter.ofLocalizedDate(FormatStyle.LONG).withLocale(Locale.getDefault()));

      } else if (patchStr.length() == SIX_DIGIT_PATCH_LEVEL) {
        int year = Integer.parseInt(patchStr.substring(0, 4));
        int month = Integer.parseInt(patchStr.substring(4, 6));
        YearMonth yearMonth = YearMonth.of(year, month);
        return yearMonth.format(DateTimeFormatter.ofPattern("MMMM yyyy", Locale.getDefault()));
      }
    } catch (RuntimeException e) {
      Log.w(TAG, "Failed to parse patch level: " + patchStr);
    }
    return patchStr;
  }

  public String formatChallenge(ByteString challenge) {
    if (challenge == null || challenge.isEmpty()) {
      return activity.getString(R.string.not_applicable);
    }

    byte[] bytes = challenge.toByteArray();

    if (isPrintableUtf8(bytes)) {
      return String.format("\"%s\" (string representation)", challenge.toStringUtf8());
    } else {
      String hex = BaseEncoding.base16().lowerCase().encode(bytes);
      return String.format("\"%s\" (hex representation)", hex);
    }
  }

  private boolean isPrintableUtf8(byte[] bytes) {
    try {
      String str = new String(bytes, StandardCharsets.UTF_8);
      return str.chars().allMatch(c -> c >= 32 && c < 127);
    } catch (RuntimeException e) {
      return false;
    }
  }

  public String formatAppId(Object appId) {
    if (appId == null) {
      return activity.getString(R.string.not_applicable);
    }
    return String.valueOf(appId).trim();
  }

  /**
   * The enforcement type of the parameter, which is either TEE, SOFTWARE, HARDWARE, or NONE.
   *
   * <p>The enforcement type is used to determine the color of the parameter and the enforcement
   * footer.
   */
  public enum EnforcementType {
    TEE("TEE"),
    SOFTWARE("SW"),
    HARDWARE("HW"),
    NONE("");

    private final String label;

    EnforcementType(String label) {
      this.label = label;
    }

    public String getLabel() {
      return label;
    }
  }
}
