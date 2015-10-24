{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns      #-}
module Data.Text.Encrypt.TemplateSpec
  ( main, spec
  ) where

import           Control.E.Keys
import           Control.E.Keys.Internal    (randomStr, removeKey)
import qualified Data.Text.Lazy             as TL
import           Data.Text.Template.Encrypt (DecryptTemplateError (..), EncryptTemplateError (..), SyntaxError (..), decrypt, encrypt)
import           Test.Hspec

main :: IO ()
main = hspec spec

spec :: Spec
spec = do
  describe "encrypt templating" $ do
    context "encrypt" $ do
      it "doesn't modify a plain text" $
        encrypt "plain text" `shouldReturn` Right "plain text"
      it "fails when closing parens are missing" $
        encrypt "hey {{where|is it?" `shouldReturn` Left (EncryptSyntaxError MissingClosingBraces)
      it "fails when plain text section is missing" $
        encrypt "hey {{where}}" `shouldReturn` Left (EncryptSyntaxError MissingPlainText)
      it "fails when publicKey is absent" $ do
        encrypt "ok {{absentKey|is absent}}" `shouldReturn` Left PublicKeyNotFound
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
        putStrLn ("Generating key <" ++ keyId ++ ">")
        generate (Just keyId)
        original <- randomStr 30
        let value = "{{" ++ keyId ++ "|" ++ original ++ "}}"
        putStrLn ("encrypt templating <" ++ value ++ ">")
        encrypt (TL.pack value) >>= \case
          Left e          -> error ("template enryption failed: " ++ show e)
          Right encrypted -> do
            putStrLn ("decrypt templating <" ++ (TL.unpack encrypted) ++ ">")
            decrypt encrypted >>= \case
              Left e                         -> error ("template decryption failed: " ++ show e)
              Right (TL.unpack -> decrypted) -> do
                putStrLn ("decrypted <" ++ decrypted ++ ">")
                decrypted `shouldBe` original
        removeKey keyId
      it "encrypts and decrypts text with number of holes" $ do
        keyId <- randomStr 10
        putStrLn ("Generating key <" ++ keyId ++ ">")
        generate (Just keyId)
        original1 <- randomStr 30
        original2 <- randomStr 30
        let value = "some text \n and more {{" ++ keyId ++ "|" ++ original1 ++ "}} more {{" ++
                    keyId ++ "|" ++ original2 ++ "}} well that's enough"
        putStrLn ("encrypt templating <" ++ value ++ ">")
        encrypt (TL.pack value) >>= \case
          Left e          -> error ("template enryption failed: " ++ show e)
          Right encrypted -> do
            putStrLn ("decrypt templating <" ++ (TL.unpack encrypted) ++ ">")
            decrypt encrypted >>= \case
              Left e                         -> error ("template decryption failed: " ++ show e)
              Right (TL.unpack -> decrypted) -> do
                putStrLn ("decrypted <" ++ decrypted ++ ">")
                decrypted `shouldBe` "some text \n and more " ++ original1 ++ " more " ++ original2 ++ " well that's enough"
        removeKey keyId
