{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.ByteString.EncryptSpec (main, spec) where

import qualified Codec.Crypto.RSA.Pure   as RSA
import           Crypto.Random.DRBG
import           Data.ByteString         (ByteString)
import           Data.Text               (Text)
import qualified Data.Text               as T (pack)
import           Test.Hspec

import           Data.ByteString.Encrypt

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "Encrypted e" $
    context "Encrypted ByteString" $
      it "have 'readEnc . showEnc ≡ id'" $ do
        let encrypted = Encrypted "keys" ("hi there" :: ByteString)
        readEnc (showEnc encrypted) `shouldBe` Just encrypted

  describe "encryption" $ do
    g :: CtrDRBG <- runIO newGenIO
    context "of bytestrings" $ do
      it "works with padded string"     $ testBS 1024 1024 g
      it "works with non-padded string" $ testBS 1023 1024 g
      it "works with short string"      $ testBS 1    1024 g
      it "works with 1024 bits key"     $ testBS 30   1024 g
      it "works with 2048 bits key"     $ testBS 12   2048 g
      it "works with 4096 bits key"     $ testBS 75   4096 g

    context "of texts" $ do
      it "works with cyrillic letters"  $ test 1024 ("тест" :: Text) g
      it "works with unicode"           $ test 1024 ("y̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆😘⛪" :: Text) g
      it "works with long strings"      $ test 1024 (T.pack (concat (replicate 10000 "very long string! " ))) g

  where

    testBS :: CryptoRandomGen g => Int -> Int -> g -> IO ()
    testBS plainSize keySize g = let Right (original, g') = genBytes plainSize g in test keySize original g'

    test :: (CryptoRandomGen g, Encryptable e) => Int -> e -> g -> IO ()
    test keySize original g = do
      let Right (publicKey, privateKey, g') = RSA.generateKeyPair g keySize
      let Right (encrypted, _) = encrypt publicKey original g'
      let Right decrypted = decrypt privateKey encrypted
      decrypted `shouldBe` original
