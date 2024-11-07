package com.android.keyattestation.verifier;

import com.google.auto.value.AutoBuilder;
import com.google.protobuf.ByteString;

/** Builder for {@link RootOfTrust}. */
@AutoBuilder(ofClass = RootOfTrust.class)
public abstract class RootOfTrustBuilder {
  public static RootOfTrustBuilder rootOfTrustBuilder() {
    return new AutoBuilder_RootOfTrustBuilder();
  }

  public static RootOfTrustBuilder rootOfTrustBuilder(RootOfTrust rootOfTrust) {
    return new AutoBuilder_RootOfTrustBuilder(rootOfTrust);
  }

  public abstract RootOfTrustBuilder setVerifiedBootKey(ByteString verifiedBootKey);

  public abstract RootOfTrustBuilder setDeviceLocked(boolean deviceLocked);

  public abstract RootOfTrustBuilder setVerifiedBootState(VerifiedBootState verifiedBootState);

  public abstract RootOfTrustBuilder setVerifiedBootHash(ByteString verifiedBootHash);

  public abstract RootOfTrust build();
}
