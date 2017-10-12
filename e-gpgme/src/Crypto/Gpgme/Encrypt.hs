module Crypto.Gpgme.Encrypt
  (
    encrypt
  , decrypt
  ) where

import Data.ByteString (ByteString)
import Crypto.Gpgme (encrypt', decrypt')

encrypt :: String -- ^ Keys filepath (like @"~/.gnupg"@)
        -> ByteString -- ^ KeyId
        -> ByteString -- ^ Plain text
        -> IO (Either String ByteString)
encrypt = encrypt'

decrypt :: String -- ^ Keys filepath (like @"~/.gnupg"@)
        -> ByteString -- ^ Ciphered text
        -> IO (Either String ByteString)
decrypt keysFP c = mapLeft show <$> decrypt' keysFP c

mapBoth :: (a -> c) -> (b -> d) -> Either a b -> Either c d
mapBoth f _ (Left x)  = Left (f x)
mapBoth _ f (Right x) = Right (f x)

mapLeft :: (a -> c) -> Either a b -> Either c b
mapLeft f = mapBoth f id
