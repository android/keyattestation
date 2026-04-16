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

import static java.nio.charset.StandardCharsets.UTF_8;

import android.content.res.AssetFileDescriptor;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.core.content.ContextCompat;
import com.android.keyattestation.verifier.AuthorizationList;
import com.android.keyattestation.verifier.GoogleTrustAnchors;
import com.android.keyattestation.verifier.KeyDescription;
import com.android.keyattestation.verifier.ProvisioningInfoMap;
import com.android.keyattestation.verifier.RootOfTrust;
import com.android.keyattestation.verifier.VerificationResult;
import com.android.keyattestation.verifier.Verifier;
import com.android.keyattestation.verifier.X509CertificateExtKt;
import com.android.keyattestation.verifier.challengecheckers.ChallengeMatcher;
import com.android.keyattestation.verifier.provider.KeyAttestationCertPath;
import com.google.android.libraries.security.content.SafeContentResolver;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.common.io.BaseEncoding;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/** Main activity for the Attestation Verifier app. */
public class MainActivity extends AppCompatActivity {
  private static final String TAG = "MainActivity";
  private static final String KEY_ALIAS = "attestation_key";
  private Button attestButton;
  private Button exportButton;
  private AttestationUiManager uiManager;

  private LinearLayout attestationContainer;
  private LinearLayout keymasterContainer;
  private LinearLayout authListContainer;

  private View attestationCard;
  private View keymasterCard;
  private View authListCard;

  private boolean showAllDetails = false;
  private boolean attestDeviceProps = true;
  private boolean useStrongbox = false;

  private ExecutorService executorService;
  private Handler handler;
  private List<X509Certificate> certChain;
  private ActivityResultLauncher<String> exportCertChainLauncher;

  private int currentTaskId = 0;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    uiManager = new AttestationUiManager(this);
    uiManager.setupActionBar();

    attestButton = findViewById(R.id.attest_button);
    exportButton = findViewById(R.id.export_button);

    attestationContainer = findViewById(R.id.attestation_container);
    keymasterContainer = findViewById(R.id.keymaster_container);
    authListContainer = findViewById(R.id.auth_list_container);

    attestationCard = findViewById(R.id.attestation_card);
    keymasterCard = findViewById(R.id.keymaster_card);
    authListCard = findViewById(R.id.auth_list_card);
    SwitchMaterial idToggle = findViewById(R.id.toggle_id_attestation);
    idToggle.setChecked(attestDeviceProps);

    idToggle.setOnCheckedChangeListener(
        (buttonView, isChecked) -> {
          attestDeviceProps = isChecked;
          resetAndAttest();
        });

    executorService = Executors.newSingleThreadExecutor();
    handler = new Handler(Looper.getMainLooper());

    attestButton.setOnClickListener(unused -> resetAndAttest());

    exportCertChainLauncher =
        registerForActivityResult(
            new ActivityResultContracts.CreateDocument("application/x-pem-file"),
            this::exportCertChain);

    exportButton.setOnClickListener(unused -> showExportInstructions());
  }

  private void resetAndAttest() {
    currentTaskId++;
    final int taskId = currentTaskId;

    attestationContainer.removeAllViews();
    keymasterContainer.removeAllViews();
    authListContainer.removeAllViews();

    attestationCard.setVisibility(View.GONE);
    keymasterCard.setVisibility(View.GONE);
    authListCard.setVisibility(View.GONE);

    exportButton.setEnabled(false);
    certChain = null;

    View summaryCard = findViewById(R.id.summary_card);
    if (summaryCard != null) {
      summaryCard.setVisibility(View.GONE);
    }

    executorService.execute(
        () -> {
          if (!runPreChecks()) {
            return;
          }
          try {
            generateAndVerifyAttestation(taskId);
          } catch (Exception e) {
            Log.e(TAG, "Attestation failed", e);
            if (taskId == currentTaskId) {
              handler.post(
                  () ->
                      addAttestationRow(
                          attestationContainer,
                          AttestationUiManager.AttestationParameter.ERROR,
                          e.getMessage(),
                          null));
            }
          }
        });
  }

  @Override
  public boolean onCreateOptionsMenu(Menu menu) {
    getMenuInflater().inflate(R.menu.main_menu, menu);
    return true;
  }

  @Override
  public boolean onPrepareOptionsMenu(Menu menu) {
    menu.findItem(R.id.menu_show_all).setChecked(showAllDetails);
    return super.onPrepareOptionsMenu(menu);
  }

  @Override
  public boolean onOptionsItemSelected(MenuItem item) {
    int id = item.getItemId();
    if (id == R.id.menu_use_strongbox) {
      item.setChecked(!item.isChecked());
      this.useStrongbox = item.isChecked();
      return true;
    } else if (id == R.id.menu_show_all) {
      item.setChecked(!item.isChecked());
      showAllDetails = item.isChecked();
      resetAndAttest();
      return true;
    } else if (id == R.id.menu_save_to_file) {
      showExportInstructions();
      return true;
    } else if (id == R.id.menu_about) {
      uiManager.showAboutDialog();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }

  private void exportCertChain(Uri uri) {
    try (AssetFileDescriptor fd = SafeContentResolver.openAssetFileDescriptor(this, uri, "wt");
        OutputStream out = fd.createOutputStream()) {
      for (X509Certificate cert : certChain) {
        out.write("-----BEGIN CERTIFICATE-----\n".getBytes(UTF_8));
        out.write(
            Base64.getEncoder()
                .encodeToString(cert.getEncoded())
                .replaceAll("(.{64})", "$1\n")
                .getBytes(UTF_8));
        out.write("\n-----END CERTIFICATE-----\n".getBytes(UTF_8));
      }
    } catch (Exception e) {
      Log.e(TAG, "Export failed", e);
    }
  }

  private void addAttestationRow(
      ViewGroup container,
      AttestationUiManager.AttestationParameter parameter,
      Object value,
      AttestationUiManager.EnforcementType enforcement) {
    String name = getString(parameter.getLabelResId());
    if (value == null || String.valueOf(value).trim().isEmpty()) {
      return;
    }

    handler.post(
        () -> {
          View itemView = getLayoutInflater().inflate(R.layout.attestation_item, container, false);
          TextView titleView = itemView.findViewById(R.id.item_title);
          TextView summaryView = itemView.findViewById(R.id.item_summary);
          TextView enforcementView = itemView.findViewById(R.id.item_enforcement);

          titleView.setText(name);
          summaryView.setText(String.valueOf(value));
          AttestationUiManager.EnforcementType type =
              (enforcement != null) ? enforcement : AttestationUiManager.EnforcementType.NONE;
          enforcementView.setText(type.getLabel());

          int colorRes =
              switch (type) {
                case TEE, HARDWARE -> R.color.brand_success;
                case SOFTWARE -> R.color.brand_warning;
                case NONE -> 0;
              };

          if (colorRes != 0) {
            enforcementView.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.ic_shield, 0);
            enforcementView.setCompoundDrawableTintList(
                ColorStateList.valueOf(ContextCompat.getColor(this, colorRes)));
          } else {
            enforcementView.setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0);
          }

          itemView.setOnClickListener(
              v ->
                  uiManager.showParameterDetailDialog(
                      name, uiManager.getParameterDescription(parameter, enforcement)));

          container.addView(itemView);
          if (container.getParent() instanceof View) {
            ((View) container.getParent()).setVisibility(View.VISIBLE);
          }
        });
  }

  private String mapPurposeToString(BigInteger p) {
    return switch (p.intValue()) {
      case 1 -> getString(R.string.purpose_sign);
      case 2 -> getString(R.string.purpose_verify);
      case 3 -> getString(R.string.purpose_encrypt);
      case 4 -> getString(R.string.purpose_decrypt);
      case 10 -> getString(R.string.purpose_attest);
      default -> getString(R.string.purpose_unknown, p.toString());
    };
  }

  private String mapAuthTypeToString(int val) {
    return switch (val) {
      case 1 -> getString(R.string.auth_type_password);
      case 2 -> getString(R.string.auth_type_biometric);
      default -> getString(R.string.auth_type_none);
    };
  }

  private void showExportInstructions() {
    handler.post(
        () -> {
          new MaterialAlertDialogBuilder(this)
              .setTitle(getString(R.string.export_certificate_chain_title))
              .setMessage(getString(R.string.export_certificate_chain_dialog_message))
              .setPositiveButton(
                  "Continue",
                  (dialog, which) -> exportCertChainLauncher.launch("attestation_certs.pem"))
              .setNegativeButton("Cancel", null)
              .show();
        });
  }

  private boolean runPreChecks() {

    if (!AttestationUtils.isNetworkAvailable(this)) {
      handler.post(
          () ->
              AttestationUtils.showAlertDialog(
                  this,
                  getString(R.string.network_error_alert_dialog_title),
                  getString(R.string.network_error_alert_dialog_msg),
                  getString(R.string.ok)));
      return false;
    }
    return true;
  }

  private void handleAttestationError(Exception e) {
    if (AttestationUtils.isCannotAttestIdsError(e)) {
      handler.post(
          () -> {
            String message = getString(R.string.cannot_attest_ids_alert_dialog_msg);
            if (attestDeviceProps) {
              message += getString(R.string.cannot_attest_ids_tip);
            }
            AttestationUtils.showAlertDialog(
                this,
                getString(R.string.cannot_attest_ids_alert_dialog_title),
                message,
                getString(R.string.ok));
          });
    } else if (AttestationUtils.isNetworkError(e)) {
      handler.post(
          () ->
              AttestationUtils.showAlertDialog(
                  this,
                  getString(R.string.network_error_alert_dialog_title),
                  getString(R.string.network_error_alert_dialog_msg),
                  getString(R.string.ok)));
    } else {
      handler.post(
          () ->
              AttestationUtils.showAlertDialog(
                  this,
                  getString(R.string.unexpected_error_alert_dialog_title),
                  getString(R.string.unexpected_error_alert_dialog_msg),
                  getString(R.string.ok)));
    }
  }

  private void generateAndVerifyAttestation(int taskId)
      throws GeneralSecurityException, IOException {

    // Generate a new key pair in the Android Keystore.
    KeyPairGenerator keyPairGenerator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
    // The attestation challenge is a random nonce that is used to prevent replay attacks.
    byte[] challenge = UUID.randomUUID().toString().getBytes(UTF_8);
    KeyGenParameterSpec spec =
        new KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .setDevicePropertiesAttestationIncluded(attestDeviceProps)
            .setIsStrongBoxBacked(useStrongbox)
            .build();

    try {
      keyPairGenerator.initialize(spec);
      keyPairGenerator.generateKeyPair();
    } catch (Exception e) {
      handleAttestationError(e);
      return;
    }

    KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
    keyStore.load(null);
    Certificate[] certs = keyStore.getCertificateChain(KEY_ALIAS);
    this.certChain =
        Arrays.stream(certs).map(c -> (X509Certificate) c).collect(Collectors.toList());

    KeyAttestationCertPath certPath = new KeyAttestationCertPath(this.certChain);
    KeyDescription ext = X509CertificateExtKt.keyDescription(certPath.leafCert());
    var unused = ProvisioningInfoMap.parseFrom(certPath.attestationCert());

    Verifier verifier =
        new Verifier(GoogleTrustAnchors.INSTANCE, Collections::emptySet, Instant::now);
    VerificationResult result = verifier.verify(certChain, new ChallengeMatcher(challenge));

    handler.post(
        () -> {
          if (taskId != currentTaskId) {
            return;
          }
          exportButton.setEnabled(true);

          boolean isVerified = (result instanceof VerificationResult.Success);
          uiManager.updateSummaryStatus(isVerified);
          String resultName = isVerified ? "Success" : result.getClass().getSimpleName();

          addAttestationRow(
              attestationContainer,
              AttestationUiManager.AttestationParameter.VERIFICATION_RESULT,
              resultName,
              isVerified
                  ? AttestationUiManager.EnforcementType.TEE
                  : AttestationUiManager.EnforcementType.SOFTWARE);
          addAttestationRow(
              attestationContainer,
              AttestationUiManager.AttestationParameter.ATTESTATION_CHALLENGE,
              uiManager.formatChallenge(ext.getAttestationChallenge()),
              AttestationUiManager.EnforcementType.NONE);
          addAttestationRow(
              attestationContainer,
              AttestationUiManager.AttestationParameter.ATTESTATION_SECURITY_LEVEL,
              ext.getAttestationSecurityLevel().name(),
              AttestationUiManager.EnforcementType.TEE);
          addAttestationRow(
              keymasterContainer,
              AttestationUiManager.AttestationParameter.KEYMASTER_VERSION,
              ext.getKeyMintVersion(),
              AttestationUiManager.EnforcementType.TEE);
          addAttestationRow(
              keymasterContainer,
              AttestationUiManager.AttestationParameter.KEYMASTER_SECURITY_LEVEL,
              ext.getKeyMintSecurityLevel().name(),
              AttestationUiManager.EnforcementType.TEE);
          AuthorizationList sw = ext.getSoftwareEnforced();
          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.CREATION_DATE,
              uiManager.formatDate(sw.getCreationDateTime()),
              AttestationUiManager.EnforcementType.SOFTWARE);
          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.APPLICATION_ID,
              uiManager.formatAppId(sw.getAttestationApplicationId()),
              AttestationUiManager.EnforcementType.SOFTWARE);

          AuthorizationList hw = ext.getHardwareEnforced();
          if (hw.getPurposes() != null) {
            String purposes =
                hw.getPurposes().stream()
                    .map(this::mapPurposeToString)
                    .collect(Collectors.joining(", "));
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ATTESTATION_PURPOSES,
                purposes,
                AttestationUiManager.EnforcementType.TEE);
          }

          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.ATTESTATION_ALGORITHMS,
              hw.getAlgorithms(),
              AttestationUiManager.EnforcementType.TEE);
          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.ATTESTATION_OS_VERSION,
              hw.getOsVersion(),
              AttestationUiManager.EnforcementType.TEE);
          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.ATTESTATION_OS_PATCH,
              uiManager.formatPatchLevel(hw.getOsPatchLevel()),
              AttestationUiManager.EnforcementType.TEE);
          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.ATTESTATION_ORIGIN,
              hw.getOrigin(),
              AttestationUiManager.EnforcementType.TEE);
          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.ATTESTATION_ID_BRAND,
              hw.getAttestationIdBrand(),
              AttestationUiManager.EnforcementType.TEE);
          addAttestationRow(
              authListContainer,
              AttestationUiManager.AttestationParameter.APPLICATION_ID,
              hw.getAttestationIdDevice(),
              AttestationUiManager.EnforcementType.TEE);

          if (hw.getRootOfTrust() != null) {
            RootOfTrust rot = hw.getRootOfTrust();
            uiManager.updateBootloaderBanner(rot.getDeviceLocked());
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ROT_STATE,
                rot.getVerifiedBootState().name(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ROT_LOCKED,
                rot.getDeviceLocked(),
                AttestationUiManager.EnforcementType.HARDWARE);
          }

          if (showAllDetails) {
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ACTIVE_DATE,
                uiManager.formatDate(hw.getActiveDateTime()),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ORIGINATION_EXPIRE_DATE,
                uiManager.formatDate(hw.getOriginationExpireDateTime()),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.USAGE_EXPIRE_DATE,
                uiManager.formatDate(hw.getUsageExpireDateTime()),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.NO_AUTH_REQUIRED,
                hw.getNoAuthRequired(),
                AttestationUiManager.EnforcementType.TEE);
            int authTypeVal = (hw.getUserAuthType() != null) ? hw.getUserAuthType().intValue() : 0;
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.USER_AUTH_TYPE,
                mapAuthTypeToString(authTypeVal),
                AttestationUiManager.EnforcementType.TEE);

            if (hw.getAuthTimeout() != null) {
              int timeoutSeconds = hw.getAuthTimeout().intValue();
              String formattedTimeout =
                  getResources()
                      .getQuantityString(R.plurals.unit_seconds, timeoutSeconds, timeoutSeconds);
              addAttestationRow(
                  authListContainer,
                  AttestationUiManager.AttestationParameter.AUTH_TIMEOUT,
                  formattedTimeout,
                  AttestationUiManager.EnforcementType.TEE);
            }
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.TRUSTED_USER_PRESENCE_REQUIRED,
                hw.getTrustedUserPresenceRequired(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.UNLOCKED_DEVICE_REQUIRED,
                hw.getUnlockedDeviceRequired(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.VENDOR_PATCH_LEVEL,
                uiManager.formatPatchLevel(hw.getVendorPatchLevel()),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.BOOT_PATCH_LEVEL,
                uiManager.formatPatchLevel(hw.getBootPatchLevel()),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ATTESTATION_ID_MODEL,
                hw.getAttestationIdModel(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ATTESTATION_ID_SERIAL,
                hw.getAttestationIdSerial(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.ATTESTATION_ID_IMEI,
                hw.getAttestationIdImei(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.KEY_SIZE,
                hw.getKeySize(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.DIGESTS,
                hw.getDigests(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.EC_CURVE,
                hw.getEcCurve(),
                AttestationUiManager.EnforcementType.TEE);
            addAttestationRow(
                authListContainer,
                AttestationUiManager.AttestationParameter.RSA_PUBLIC_EXPONENT,
                hw.getRsaPublicExponent() != null ? hw.getRsaPublicExponent().toString() : "",
                AttestationUiManager.EnforcementType.TEE);

            if (hw.getModuleHash() != null && !hw.getModuleHash().isEmpty()) {
              String hash =
                  BaseEncoding.base16().lowerCase().encode(hw.getModuleHash().toByteArray());
              addAttestationRow(
                  authListContainer,
                  AttestationUiManager.AttestationParameter.ATTESTATION_MODULE_HASH,
                  hash,
                  AttestationUiManager.EnforcementType.TEE);
            }
          }
        });
  }
}
