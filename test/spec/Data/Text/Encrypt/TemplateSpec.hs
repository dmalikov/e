{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns        #-}
module Data.Text.Encrypt.TemplateSpec
  ( main, spec
  ) where

import           Control.E.Keys
import           Control.E.Keys.Internal    (randomStr, removeKey)
import           Crypto.Random.DRBG
import qualified Data.Text.Lazy             as TL
import           Data.Text.Template.Encrypt (DecryptTemplateError (..), EncryptTemplateError (..), SyntaxError (..), decrypt, encrypt)
import           Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  g :: CtrDRBG <- runIO newGenIO
  describe "encrypt templating" $ do
    context "encrypt" $ do
      it "doesn't modify a plain text" $
        fst <$> encrypt "plain text" g `shouldReturn` Right "plain text"
      it "fails when closing parens are missing" $
        fst <$> encrypt "hey {{where|is it?" g `shouldReturn` Left (EncryptSyntaxError MissingClosingBraces)
      it "fails when plain text section is missing" $
        fst <$> encrypt "hey {{where}}" g `shouldReturn` Left (EncryptSyntaxError MissingPlainText)
      it "fails when publicKey is absent" $
        fst <$> encrypt "ok {{absentKey|is absent}}" g `shouldReturn` Left PublicKeyNotFound
    context "decrypt" $ do
      it "doesn't modify a plain text" $
        decrypt "plain text" `shouldReturn` Right "plain text"
      it "fails when format is invalid" $
        decrypt "invalid {{format}}" `shouldReturn` Left (DecryptSyntaxError InvalidFormat)
      it "fails when privateKey is absent" $
        decrypt "this {{key|is|absent}} sorry" `shouldReturn` Left PrivateKeyNotFound
    context "encrypt / decrypt" $ do
      it "encrypts and decrypts text with a single hole" $ do
        keyId <- randomStr 10
        generate (Just keyId)
        original <- randomStr 30
        let value = "{{" ++ keyId ++ "|" ++ original ++ "}}"
        fst <$> encrypt (TL.pack value) g >>= \case
          Left e          -> error ("template enryption failed: " ++ show e)
          Right encrypted ->
            decrypt encrypted >>= \case
              Left e                         -> error ("template decryption failed: " ++ show e)
              Right (TL.unpack -> decrypted) -> decrypted `shouldBe` original
        removeKey keyId
      it "encrypts and decrypts text with number of holes" $ do
        keyId <- randomStr 10
        generate (Just keyId)
        original1 <- randomStr 30
        original2 <- randomStr 30
        let value = "some text \n and more {{" ++ keyId ++ "|" ++ original1 ++ "}} more {{" ++
                    keyId ++ "|" ++ original2 ++ "}} well that's enough"
        fst <$> encrypt (TL.pack value) g >>= \case
          Left e          -> error ("template enryption failed: " ++ show e)
          Right encrypted ->
            decrypt encrypted >>= \case
              Left e                         -> error ("template decryption failed: " ++ show e)
              Right (TL.unpack -> decrypted) ->
                decrypted `shouldBe` "some text \n and more " ++ original1 ++ " more " ++ original2 ++ " well that's enough"
        removeKey keyId
