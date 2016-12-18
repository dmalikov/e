{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
module GenerateEncryptDecrypt
  ( generateEncryptDecrypt
  ) where

import           Control.E.Keys.Internal (randomStr, removeKey)
import           Control.Monad           (when)
import           System.Directory        (doesFileExist)
import           System.Exit             (ExitCode (..))
import           System.FilePath         ((</>))
import           System.Process          (readProcessWithExitCode)
import           Paths_e


generateEncryptDecrypt :: IO ()
generateEncryptDecrypt = do
  keyId <- randomStr 10
  value <- randomStr 1000
  generate keyId
  encrypted <- encrypt keyId value
  decrypted <- decrypt keyId encrypted
  when (decrypted /= value) $
    error "decrypted value differs from the original one"
  removeKey keyId

generate :: String -> IO ()
generate keyId = do
  putStrLn ("Generating key <" ++ keyId ++ ">")
  getExe >>= \exe ->
    readProcessWithExitCode exe ["generate-key", keyId] "" >>= \(exitCode, _, stderr) ->
      when (exitCode /= ExitSuccess) $
        error ("generate-key failed: " ++ stderr)

encrypt :: String -> String -> IO String
encrypt keyId value = do
  putStrLn ("Encrypting <" ++ (shadow value) ++ ">")
  getExe >>= \exe ->
    readProcessWithExitCode exe ["encrypt", keyId, value] "" >>= \(exitCode, stdout, stderr) -> do
      when (exitCode /= ExitSuccess) $
        error ("encrypt failed: " ++ stderr)
      case lines stdout of
        []          -> error "encrypt returned an empty output"
        encrypted:_ -> return encrypted

decrypt :: String -> String -> IO String
decrypt keyId value = do
  putStrLn ("Decrypting <" ++ (shadow value) ++ ">")
  getExe >>= \exe ->
    readProcessWithExitCode exe ["decrypt", keyId, value] "" >>= \(exitCode, stdout, stderr) -> do
      when (exitCode /= ExitSuccess) $
        error ("decrypt failed: " ++ stderr)
      case lines stdout of
        []          -> error "encrypt returned an empty output"
        decrypted:_ -> return decrypted

getExe :: IO FilePath
getExe = do
  filepath <- (</> "e") <$> getBinDir
  doesFileExist filepath >>= \case
    True  -> return filepath
    False -> error ("unable to find e executable")

shadow :: String -> String
shadow s = take 7 s ++ "...[" ++ (show $ length s) ++ " chars long]"
