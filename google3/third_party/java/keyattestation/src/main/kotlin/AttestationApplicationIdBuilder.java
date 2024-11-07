package com.android.keyattestation.verifier;

import com.google.auto.value.AutoBuilder;
import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableSet;
import com.google.protobuf.ByteString;
import java.util.Set;

/** Builder for {@link AttestationApplicationId}. */
@AutoBuilder(ofClass = AttestationApplicationId.class)
@AutoValue.CopyAnnotations
@SuppressWarnings("JdkImmutableCollections")
public abstract class AttestationApplicationIdBuilder {
  public static AttestationApplicationIdBuilder attestationApplicationIdBuilder() {
    return new AutoBuilder_AttestationApplicationIdBuilder()
        .setPackages(ImmutableSet.of())
        .setSignatures(ImmutableSet.of());
  }

  public static AttestationApplicationIdBuilder attestationApplicationIdBuilder(
      AttestationApplicationId attestationApplicationId) {
    return new AutoBuilder_AttestationApplicationIdBuilder(attestationApplicationId);
  }

  public abstract AttestationApplicationIdBuilder setPackages(Set<AttestationPackageInfo> packages);

  public abstract AttestationApplicationIdBuilder setSignatures(Set<ByteString> signatures);

  public abstract AttestationApplicationId build();
}
