package com.android.keyattestation.verifier;

import com.google.auto.value.AutoBuilder;
import java.math.BigInteger;

/** Builder for {@link AttestationPackageInfo}. */
@AutoBuilder(ofClass = AttestationPackageInfo.class)
public abstract class AttestationPackageInfoBuilder {
  public static AttestationPackageInfoBuilder attestationPackageInfoBuilder() {
    return new AutoBuilder_AttestationPackageInfoBuilder();
  }

  public static AttestationPackageInfoBuilder attestationPackageInfoBuilder(
      AttestationPackageInfo attestationPackageInfo) {
    return new AutoBuilder_AttestationPackageInfoBuilder(attestationPackageInfo);
  }

  public abstract AttestationPackageInfoBuilder setName(String name);

  public abstract AttestationPackageInfoBuilder setVersion(BigInteger version);

  public abstract AttestationPackageInfo build();
}
