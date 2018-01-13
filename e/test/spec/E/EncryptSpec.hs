{-# Language OverloadedStrings #-}
module E.EncryptSpec (main, spec) where

import qualified Data.Text as Text
import Data.Either.MoreCombinators
import Data.Semigroup

import Test.Hspec

import E

main :: IO ()
main = hspec spec

spec :: Spec
spec = do

  describe "encryptTem" $ do

    it "accept plain value already exists in metadata if it's equal" $ do
      let meta = singleton (ValName "var") (EncValue (AlgName "dummy") mempty (EncContent "ok"))
      Right (_, meta') <- runExceptT (encryptTem dummy meta (val (PlainValue (ValName "var") (AlgName "dummy") mempty (PlainContent "ok"))))
      meta' `shouldBe` meta

    it "do not modify 'Ref'" $ do
      let meta = singleton (ValName "var") (EncValue (AlgName "dummy") mempty (EncContent "ok"))
      let tem = ref (ValRef (ValName "var"))
      Right (tem', meta') <- runExceptT (encryptTem dummy meta tem)
      tem' `shouldBe` tem
      meta' `shouldBe` meta

    it "throws AlgNotFound when encryption algorithm is unsupported" $ do
      runExceptT (encryptTem mempty mempty (val (PlainValue (ValName "var") (AlgName "unsupported") mempty (PlainContent "plain")))) `shouldReturn`
        Left (AlgNotFound (AlgName "unsupported"))

    it "throws CipherError when ciphering failed" $ do
      let failingCiphering = algorithm (AlgName "failing") (Cipher fc) (Decipher fdc)
          fc _ _ = left "failure"
          fdc = undefined
      runExceptT (encryptTem failingCiphering mempty (val (PlainValue (ValName "var") (AlgName "failing") mempty (PlainContent "plain")))) `shouldReturn`
        Left (CipherError (AlgName "failing") "failure")

    it "throws MetadataError when plain value already exists in metadata with different value" $ do
      let meta = singleton (ValName "var") (EncValue (AlgName "dummy") mempty (EncContent "ok"))
      runExceptT (encryptTem (dummy `mappend` mempty) meta (val (PlainValue (ValName "var") (AlgName "dummy") mempty (PlainContent "plain")))) `shouldReturn`
        Left (MetadataError (MetadataInconsistentValues (ValName "var")))

    it "supports Ciphers/Decipher using args" $ do
      let a = algorithm (AlgName "a") c d
          c = Cipher $ \args (PlainContent p) -> do
                ArgValue prefix <- hoistEither $ note "no prefix provided" $ lookupArg "prefix" args
                pure (EncContent $ prefix `Text.append` p)
          d = Decipher $ \args (EncContent e) -> do
                ArgValue prefix <- hoistEither $ note "no prefix provided" $ lookupArg "prefix" args
                pure (PlainContent $ Text.length prefix `Text.drop` e)
          tem = val (PlainValue (ValName "var")
                                (AlgName "a")
                                (arg (ArgName "prefix") (ArgValue "!!"))
                                (PlainContent "nice,great")) <>
                ref (ValRef (ValName "ok"))
          meta = singleton (ValName "ok")
                           (EncValue (AlgName "a")
                                     (arg (ArgName "prefix") (ArgValue "!!"))
                                     (EncContent "!! - not bad"))
          tem'' = txt "nice,great - not bad"
      runExceptT (encryptTem a meta tem >>= \(tem',meta') -> normalize <$> decryptTem a meta' tem') `shouldReturn`
        Right tem''

  describe "decryptTem" $ do

    it "throws AlgNotFound when decryption algorithm is unsupported" $ do
      let meta = singleton (ValName "var") (EncValue (AlgName "unsupported") mempty (EncContent "ok"))
      runExceptT (decryptTem mempty meta (ref (ValRef (ValName "var")))) `shouldReturn`
        Left (AlgNotFound (AlgName "unsupported"))

    it "throws ValNotFound when 'Ref' referencing absent value" $
      runExceptT (decryptTem mempty mempty (ref (ValRef (ValName "var")))) `shouldReturn`
        Left (ValNotFound (ValName "var"))

    it "throws DecipherError when deciphering failed" $ do
      let failingCiphering = algorithm (AlgName "failing") (Cipher fc) (Decipher fdc)
          fc = undefined
          fdc _ _ = left "failure"
          meta = singleton (ValName "var") (EncValue (AlgName "failing") mempty (EncContent "ok"))
      runExceptT (decryptTem failingCiphering meta (ref (ValRef (ValName "var")))) `shouldReturn`
        Left (DecipherError (AlgName "failing") "failure")

  describe "Cipher / Decipher" $ do
    it "ciphers / deciphers" $ do
      let c = Cipher   $ const (right . EncContent . unPlainContent)
      let d = Decipher $ const (right . PlainContent . unEncContent)
      runExceptT (runDecipher d undefined =<< runCipher c undefined (PlainContent "ok")) `shouldReturn`
        Right (PlainContent "ok")

  describe "EError" $ do
    it "has valid Eq instance" $
      AlgNotFound (AlgName "hm") `shouldNotBe` ValNotFound (ValName "val")
    it "has valid Show instance" $
      showList [AlgNotFound (AlgName "alg")] "" `shouldBe` "[AlgNotFound (AlgName {unAlgName = \"alg\"})]"
