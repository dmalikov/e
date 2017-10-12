{-# LANGUAGE LambdaCase                #-}
{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings         #-}
{-# LANGUAGE ScopedTypeVariables       #-}
module E.Algorithm.DummySpec (main, spec) where

import Control.Monad.Trans.Either
import Test.Hspec

import E.Algorithm.Dummy
import E.Template
import E.Encrypt

main :: IO ()
main = hspec spec

spec :: Spec
spec =
  describe "Dummy encryption" $
    context "dummy" $
      it "have 'decrypt . encrypt ≡ id'" $ do
        let Just templatePlain = decode "password = \"{{P|password|dummy||qwerty}}\""
        Right (templateCiphered, metadata) <- runEitherT $ encryptTem dummy mempty templatePlain
        Right decipheredTemplate <- runEitherT $ decryptTem dummy metadata templateCiphered
        encode decipheredTemplate `shouldBe` "password = \"qwerty\""
