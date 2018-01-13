{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE ScopedTypeVariables       #-}
module E.Algorithm.DummySpec (main, spec) where

import Test.Hspec

import E

main :: IO ()
main = hspec spec

spec :: Spec
spec =
  describe "Dummy encryption" $
    context "dummy" $
      it "have 'decrypt . encrypt ≡ id'" $ do
        let Just templatePlain = decode "password = \"{{P|password|dummy||qwerty}}\""
        Right (templateCiphered, metadata) <- runExceptT $ encryptTem dummy mempty templatePlain
        Right decipheredTemplate <- runExceptT $ decryptTem dummy metadata templateCiphered
        encode decipheredTemplate `shouldBe` "password = \"qwerty\""
