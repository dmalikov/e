{-# LANGUAGE LambdaCase          #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE ScopedTypeVariables #-}

import           Control.E.Keys
import           Crypto.Random.DRBG
import qualified Data.ByteString.Encrypt as BSE
import           Data.Monoid                    ((<>))
import qualified Data.Text               as T
import qualified Data.Text.IO            as TIO (putStrLn)
import           Options.Applicative
import qualified System.Template.Encrypt as STE


main :: IO ()
main =
  getCommand >>= \case
    Encrypt keyId plainString ->
      getStorePath >>= lookupPublic keyId >>= \case
        Nothing        -> error ("key <" ++ keyId ++ "> not found")
        Just publicKey -> do
          g :: CtrDRBG <- newGenIO
          case BSE.encrypt publicKey (T.pack plainString) g of
            Left err       -> error (show err)
            Right (enc, _) -> putStrLn (BSE.showEnc enc)
    Decrypt keyId encryptedString ->
      getStorePath >>= lookupPrivate keyId >>= \case
        Nothing         -> error ("key <" ++ keyId ++ "> not found")
        Just privateKey ->
          case BSE.readEnc encryptedString of
            Nothing        -> error ("invalid format of encrypted value <" ++ encryptedString ++ ">")
            Just encrypted ->
              case BSE.decrypt privateKey encrypted of
                Left err        -> error (show err)
                Right decrypted -> TIO.putStrLn decrypted
    EncryptFile fpsrc fpdst ->
      STE.encrypt fpsrc fpdst >>= \case
        Nothing -> return ()
        Just e  -> error (show e)
    DecryptFile fpsrc fpdst ->
      STE.decrypt fpsrc fpdst >>= \case
        Nothing -> return ()
        Just e  -> error (show e)
    GenerateKey maybeKeyId -> generate maybeKeyId
    ListKeys -> list


type KeyId     = String
type Plain     = String
type Encrypted = String
type Input     = String
type Output    = String

data Command
  = Encrypt KeyId Plain
  | Decrypt KeyId Encrypted
  | EncryptFile Input Output
  | DecryptFile Input Output
  | GenerateKey (Maybe KeyId)
  | ListKeys

getCommand :: IO Command
getCommand = execParser $ info (helper <*> commandParser) (fullDesc <> progDesc "e")

encrypt :: Parser Command
encrypt = Encrypt
   <$> argument str (metavar "keyId")
   <*> argument str (metavar "plainText")

decrypt :: Parser Command
decrypt = Decrypt
   <$> argument str (metavar "keyId")
   <*> argument str (metavar "plainText")

encryptFile :: Parser Command
encryptFile = EncryptFile
   <$> argument str (metavar "input")
   <*> argument str (metavar "output")

decryptFile :: Parser Command
decryptFile = DecryptFile
   <$> argument str (metavar "input")
   <*> argument str (metavar "output")

generateKey :: Parser Command
generateKey = GenerateKey
   <$> optional (argument str (metavar "keyId"))

commandParser :: Parser Command
commandParser = subparser
  $  command "encrypt" (info encrypt
      (progDesc "Encrypt given string using a public key with given keyId"))
  <> command "decrypt" (info decrypt
      (progDesc "Decrypt given string using a private key with given keyId"))
  <> command "encrypt-file" (info encryptFile
      (progDesc "Encrypt given file using a public key with given keyId"))
  <> command "decrypt-file" (info decryptFile
      (progDesc "Decrypt given file using a private key with given keyId"))
  <> command "generate-key" (info generateKey
      (progDesc "Generate key with a given keyId"))
  <> command "list-keys" (info (pure ListKeys)
      (progDesc "List avaiable keys"))
