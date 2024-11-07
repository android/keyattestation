package com.android.keyattestation.verifier;

import com.google.auto.value.AutoBuilder;
import com.google.protobuf.ByteString;
import java.math.BigInteger;

/** Builder for {@link KeyDescription}. */
@AutoBuilder(ofClass = KeyDescription.class)
public abstract class KeyDescriptionBuilder {
  public static KeyDescriptionBuilder keyDescriptionBuilder() {
    return new AutoBuilder_KeyDescriptionBuilder();
  }

  public static KeyDescriptionBuilder keyDescriptionBuilder(KeyDescription keyDescription) {
    return new AutoBuilder_KeyDescriptionBuilder(keyDescription);
  }

  public abstract KeyDescriptionBuilder setAttestationVersion(BigInteger attestationVersion);

  public abstract KeyDescriptionBuilder setAttestationSecurityLevel(
      SecurityLevel attestationSecurityLevel);

  public abstract KeyDescriptionBuilder setKeymasterVersion(BigInteger keymasterVersion);

  public abstract KeyDescriptionBuilder setKeymasterSecurityLevel(
      SecurityLevel keymasterSecurityLevel);

  public abstract KeyDescriptionBuilder setAttestationChallenge(ByteString attestationChallenge);

  public abstract KeyDescriptionBuilder setUniqueId(ByteString uniqueId);

  public abstract KeyDescriptionBuilder setSoftwareEnforced(AuthorizationList softwareEnforced);

  public abstract KeyDescriptionBuilder setTeeEnforced(AuthorizationList teeEnforced);

  public abstract KeyDescription build();
}
