package com.android.keyattestation.verifier;

import com.google.auto.value.AutoBuilder;
import com.google.auto.value.AutoValue.CopyAnnotations;
import java.math.BigInteger;
import java.util.Set;

/** Builder for {@link AuthorizationList}. */
@CopyAnnotations
@SuppressWarnings("JdkImmutableCollections")
@AutoBuilder(ofClass = AuthorizationList.class)
public abstract class AuthorizationListBuilder {
  public static AuthorizationListBuilder authorizationListBuilder() {
    return new AutoBuilder_AuthorizationListBuilder();
  }

  public static AuthorizationListBuilder authorizationListBuilder(
      AuthorizationList authorizationList) {
    return new AutoBuilder_AuthorizationListBuilder(authorizationList);
  }

  public abstract AuthorizationListBuilder setPurposes(Set<BigInteger> purpose);

  public abstract AuthorizationListBuilder setAlgorithms(BigInteger algorithm);

  public abstract AuthorizationListBuilder setKeySize(BigInteger keySize);

  public abstract AuthorizationListBuilder setDigests(Set<BigInteger> digests);

  public abstract AuthorizationListBuilder setPaddings(Set<BigInteger> paddings);

  public abstract AuthorizationListBuilder setEcCurve(BigInteger ecCurve);

  public abstract AuthorizationListBuilder setRsaPublicExponent(BigInteger rsaPublicExponent);

  public abstract AuthorizationListBuilder setActiveDateTime(BigInteger activeDateTime);

  public abstract AuthorizationListBuilder setOriginationExpireDateTime(
      BigInteger originationExpireDateTime);

  public abstract AuthorizationListBuilder setUsageExpireDateTime(BigInteger usageExpireDateTime);

  public abstract AuthorizationListBuilder setNoAuthRequired(boolean noAuthRequired);

  public abstract AuthorizationListBuilder setUserAuthType(BigInteger userAuthType);

  public abstract AuthorizationListBuilder setTrustedUserPresenceRequired(
      boolean trustedUserPresenceRequired);

  public abstract AuthorizationListBuilder setAuthTimeout(BigInteger authTimeout);

  public abstract AuthorizationListBuilder setCreationDateTime(BigInteger creationDateTime);

  public abstract AuthorizationListBuilder setOrigin(BigInteger origin);

  public abstract AuthorizationListBuilder setRollbackResistant(boolean rollbackResistant);

  public abstract AuthorizationListBuilder setRootOfTrust(RootOfTrust rootOfTrust);

  public abstract AuthorizationListBuilder setOsVersion(BigInteger osVersion);

  public abstract AuthorizationListBuilder setOsPatchLevel(BigInteger osPatchLevel);

  public abstract AuthorizationListBuilder setAttestationApplicationId(
      AttestationApplicationId attestationApplicationId);

  public abstract AuthorizationListBuilder setAttestationIdBrand(String attestationIdBrand);

  public abstract AuthorizationListBuilder setAttestationIdDevice(String attestationIdDevice);

  public abstract AuthorizationListBuilder setAttestationIdProduct(String attestationIdProduct);

  public abstract AuthorizationListBuilder setAttestationIdSerial(String attestationIdSerial);

  public abstract AuthorizationListBuilder setAttestationIdImei(String attestationIdImei);

  public abstract AuthorizationListBuilder setAttestationIdMeid(String attestationIdMeid);

  public abstract AuthorizationListBuilder setAttestationIdManufacturer(
      String attestationIdManufacturer);

  public abstract AuthorizationListBuilder setAttestationIdModel(String attestationIdModel);

  public abstract AuthorizationListBuilder setVendorPatchLevel(BigInteger vendorPatchLevel);

  public abstract AuthorizationListBuilder setBootPatchLevel(BigInteger bootPatchLevel);

  public abstract AuthorizationListBuilder setAttestationIdSecondImei(
      String attestationIdSecondImei);

  public abstract AuthorizationList build();
}
