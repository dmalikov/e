{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module Data.ByteString.EncryptSpec (main, spec) where

import qualified Codec.Crypto.RSA.Pure   as RSA
import           Crypto.Random.DRBG      (CtrDRBG, genBytes, newGenIO)
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS
import           Data.Text               (Text)
import qualified Data.Text               as T (pack)
import           Test.Hspec

import           Data.ByteString.Encrypt

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "Encrypted e" $ do
    context "Encrypted ByteString" $ do
      it "have 'readEnc . showEnc ≡ id'" $ do
        let encrypted = (Encrypted "keys" ("hi there" :: ByteString))
        readEnc (showEnc encrypted) `shouldBe` Just encrypted

  describe "encryption" $ do
    context "of bytestrings" $ do
      it "works with padded string"     $ testBS 1024 1024
      it "works with non-padded string" $ testBS 1023 1024
      it "works with short string"      $ testBS 1    1024
      it "works with 1024 bits key"     $ testBS 30   1024
      it "works with 2048 bits key"     $ testBS 12   2048
      it "works with 4096 bits key"     $ testBS 75   4096

    context "of texts" $ do
      it "works with cyrillic letters"  $ test ("тест" :: Text) 1024
      it "works with unicode"           $ test ("y̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆̆😘⛪" :: Text) 1024
      it "works with long strings"      $ test (T.pack (concat (take 10000 (repeat "very long string! " )))) 1024

  where

    testBS :: Int -> Int -> IO ()
    testBS plainSize keySize = do
      original <- generateBytes plainSize
      test original keySize

    test :: Encryptable e => e -> Int -> IO ()
    test original keySize = do
      gen <- newGenIO :: IO CtrDRBG
      let Right (publicKey, privateKey, _) = RSA.generateKeyPair gen keySize
      Right encrypted <- encrypt publicKey original
      Right decrypted <- decrypt privateKey encrypted
      decrypted `shouldBe` original
      putStrLn ("original value:  " ++ show original)
      putStrLn ("encrypted value: " ++ showEnc encrypted)
      putStrLn ("decrypted value: " ++ show decrypted)

generateBytes :: Int -> IO BS.ByteString
generateBytes n = do
  gen <- newGenIO :: IO CtrDRBG
  case genBytes n gen of
    Right (bytes, _) -> return bytes
    Left e           -> error (show e)
