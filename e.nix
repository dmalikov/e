{ mkDerivation, base, base64-bytestring, bytestring, cipher-aes
, crypto-cipher-types, directory, DRBG, filepath, hspec
, optparse-applicative, process, random, RSA, stdenv, text
, unordered-containers
}:
mkDerivation {
  pname = "e";
  version = "0.0.0";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  buildDepends = [
    base base64-bytestring bytestring cipher-aes crypto-cipher-types
    directory DRBG filepath optparse-applicative random RSA text
    unordered-containers
  ];
  testDepends = [
    base base64-bytestring bytestring cipher-aes crypto-cipher-types
    directory DRBG filepath hspec process random RSA text
  ];
  description = "Text encrypting using RSA and AES-GCM";
  license = stdenv.lib.licenses.mit;
}
