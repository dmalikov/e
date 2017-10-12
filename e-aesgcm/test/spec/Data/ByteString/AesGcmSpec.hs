{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE ScopedTypeVariables       #-}
module Data.ByteString.AesGcmSpec (main, spec) where

import qualified Codec.Crypto.RSA.Pure  as RSA
import           Crypto.Random.DRBG
import           Data.ByteString        (ByteString)

import           Test.Hspec
import           Test.Hspec.QuickCheck
import           Test.QuickCheck
import           Test.QuickCheck.Instances ()

import           Data.ByteString.AesGcm

main :: IO ()
main = hspec spec

spec :: Spec
spec = 
  describe "AesGcm ciphering" $ do
    it "have 'readEnc . showEnc ≡ id'" $ do
      let encrypted = Encrypted "keys" ("hi there" :: ByteString)
      readEnc (showEnc encrypted) `shouldBe` Just encrypted

    g :: CtrDRBG <- runIO newGenIO

    prop "works with 2048 bits key" $
      forAll (elements [1024, 2048, 4096] :: Gen Int) $ \keySize ->
      forAll (arbitrary :: Gen ByteString) $ \original -> do
        let Right (publicKey, privateKey, g') = RSA.generateKeyPair g keySize
        let Right (encrypted, _) = encrypt publicKey original g'
        let Right decrypted = decrypt privateKey encrypted
        decrypted `shouldBe` original
