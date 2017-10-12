{-# Language OverloadedStrings #-}
{-# Language ScopedTypeVariables #-}
{-# Language GeneralizedNewtypeDeriving #-}

{-| A text file with sensitive data.

'Tem' could contain plain text, plain values 'PlainValue' that would be encrypted, and references to already encrypted values 'ValRef'.

=== 'PlainValue' syntax

@{{P|\<variable name\>|\<encryption algorithm name\>|\<arguments\>|\<content\>}}@

E.g. @{{P|username|gpgme|keyId = foobar|dmalikov}}@.

=== 'ValRef' syntax
@{{E|\<variable name\>}}@

E.g. @{{E|username}}@.

- @\<variable name\>@. Name of the variable stored in 'Metadata' which could be referenced in 'ValRef'.
- @\<encryption algorithm name\>@. 'AlgName' provided by one of the algorithms 'Algs' used for encryption/decryption.
- @\<arguments\>@. Arguments that encryption algorithm 'Algs' use during encryption/decryption.
- @\<content\>@. Sensitive data to encrypt.

-}

module E.Template
  (
  -- * Template
    Tem(..)
  , txt
  , val
  , ref
  -- ** Value
  , PlainValue(..)
  , PlainContent(..)
  , EncValue(..)
  , EncContent(..)
  , ValName(..)
  , ValRef(..)
  -- ** Encryption/decryption arguments
  , Args(..)
  , ArgName(..)
  , ArgValue(..)
  , AlgName(..)
  -- ** Args operations
  , arg
  , lookupArg
  -- ** Operations on 'Tem'
  , normalize
  -- * Parsers
  , parseMaybe
  , parseArgNV
  , parseArgs
  , parsePlainValue
  , parseValRef
  , parseTem
  -- * Serializing routines
  , Serialize(..)
  ) where

import Control.Applicative
import Control.Arrow ((***))
import Control.Monad (MonadPlus)
import Data.Functor (void)
import Data.HashMap.Strict (HashMap)
import qualified Data.HashMap.Strict as Map
import Data.Hashable
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Aeson hiding (encode, Value, Result, Success)
import Data.Semigroup
import Data.Attoparsec.Text
import Data.Attoparsec.Combinator
import Text.Parser.Token (commaSep)

-- | Representation of encrypted and/or to-be-encrypted content.
data Tem
  = Nil                             -- ^ End of 'Tem'.
  | {-# UNPACK #-} !Text `Txt` !Tem -- ^ Chunk with text.
  | !PlainValue `Val` !Tem          -- ^ Chunk with plain value (intended to be encrypted).
  | !ValRef `Ref` !Tem              -- ^ Chunk with reference to already encrypted value.
    deriving (Eq,Show)

-- | Convert @Text@ to @Tem@.
txt :: Text -> Tem
txt t = t `Txt` Nil
{-# INLINE txt #-}

-- | Convert @PlainValue@ to @Tem@.
val :: PlainValue -> Tem
val p = p `Val` Nil
{-# INLINE val #-}

-- | Convert @ValRef@ to @Tem@.
ref :: ValRef -> Tem
ref p = p `Ref` Nil
{-# INLINE ref #-}

instance Semigroup Tem where
  Nil <> t = t
  t <> Nil = t
  text `Txt` s <> t = text `Txt` (s <> t)
  plain `Val` s <> t = plain `Val` (s <> t)
  r `Ref` s <> t = r `Ref` (s <> t)
  {-# INLINE (<>) #-}

instance Monoid Tem where
  mempty = Nil
  {-# INLINE mempty #-}
  mappend = (<>)
  {-# INLINE mappend #-}

-- | Representation of plain value.
data PlainValue = PlainValue !ValName !AlgName !Args !PlainContent
  deriving (Eq,Show)

-- | Representation of encrypted value (in @Metadata@).
data EncValue = EncValue !AlgName !Args !EncContent
  deriving (Eq,Show)

instance FromJSON EncValue where
  parseJSON = withObject "EncValue" $ \o -> EncValue
    <$> (AlgName <$> o .: "alg")
    <*> (o .:? "args" .!= mempty)
    <*> (EncContent <$> o .: "value")

instance ToJSON EncValue where
  toJSON (EncValue algName args content) =
    object $
      [ "alg" .= unAlgName algName
      , "value" .= unEncContent content
      ] ++
      if args == mempty
        then []
        else [ "args" .= toJSON args ]

-- | Plain text.
data PlainContent = PlainContent { unPlainContent :: {-# UNPACK #-} !Text }
  deriving (Eq,Show)

-- | Ciphered text.
data EncContent = EncContent { unEncContent :: {-# UNPACK #-} !Text }
  deriving (Eq,Show)

-- | Value name.
newtype ValName = ValName { unValName :: Text }
  deriving (Ord,Eq,Show,Hashable,FromJSONKey,ToJSONKey)

-- | Encryption/decryption algorithm name. E.g. 'gpg'.
newtype AlgName = AlgName { unAlgName :: Text }
  deriving (Ord,Eq,Show,Hashable)

-- | Bunch of arguments that could be useful for encryption/decryption.
data Args = Args { unArgs :: HashMap ArgName ArgValue }
  deriving (Eq,Show)

instance FromJSON Args where
  parseJSON = fmap (Args . Map.fromList . map (ArgName *** ArgValue) . Map.toList) . parseJSON

instance ToJSON Args where
  toJSON = object . map (\(k, v) -> unArgName k .= unArgValue v) . Map.toList . unArgs

-- | Semigroup over inner map.
instance Semigroup Args where
  Args xs <> Args ys = Args (xs <> ys)

-- | Monoid over inner map.
instance Monoid Args where
  mappend = (<>)
  mempty = Args mempty

-- | @Args@ constructor.
arg :: ArgName -> ArgValue -> Args
arg n v = Args (Map.singleton n v)

-- | Typed key of 'Args' hashmap.
data ArgName = ArgName { unArgName :: {-# UNPACK #-} !Text }
  deriving (Eq,Show)

instance Hashable ArgName where
  hashWithSalt s (ArgName t) = s + hash t

-- | Typed value of 'Args' hashmap.
data ArgValue = ArgValue { unArgValue :: {-# UNPACK #-} !Text }
  deriving (Eq,Show)

-- | Lookup arg.
lookupArg :: Text -> Args -> Maybe ArgValue
lookupArg k m = Map.lookup (ArgName k) (unArgs m)
{-# INLINE lookupArg #-}

-- | Reference to an encrypted value.
data ValRef = ValRef { unValRef :: !ValName }
  deriving (Eq,Show)

-- | Normalize 'Tem' squashing all neighboring 'Txt' chunks.
normalize :: Tem -> Tem
normalize Nil                  = Nil
normalize (Val v rest)         = Val v (normalize rest)
normalize (Ref r rest)         = Ref r (normalize rest)
normalize (Txt t (Txt s rest)) = normalize (Txt (t `Text.append` s) rest)
normalize (Txt t rest)         = Txt t (normalize rest)

-- | 'Parser' for 'Args'.
parseArgs :: Parser Args
parseArgs = Args . Map.fromList <$> commaSep parseArgNV
{-# INLINE parseArgs #-}

-- | 'Parser' for key-value pair ('ArgName', 'ArgValue').
parseArgNV :: Parser (ArgName, ArgValue)
parseArgNV = (,)
  <$> (ArgName <$> word )
  <*> (ArgValue <$> (char '=' *> word))

-- | 'Parser' for a word (bunch of letter and digits).
word :: Parser Text
word = Text.pack <$> (spaces *> some (letter <|> digit) <* spaces)
{-# INLINE word #-}

-- Like manyTill, but pack the result to Text.
textTill' :: MonadPlus f => f Char -> f b -> f Text
textTill' p end = Text.pack <$> manyTill' p end
{-# INLINE textTill' #-}

-- | many space.
spaces :: Parser [Char]
spaces = many space
{-# INLINE spaces #-}
{-# ANN module ("HLint: ignore Use String" :: String) #-}

-- | Apply parser and maybe return result.
parseMaybe :: Parser a -> Text -> Maybe a
parseMaybe p t =
  case parseOnly p t of
    Right r -> Just r
    _       -> Nothing

-- | 'Parser' for 'PlainValue'.
parsePlainValue :: Parser PlainValue
parsePlainValue = PlainValue
  <$> (ValName <$> (string "{{P|" *> spaces *> word <* sep))
  <*> (AlgName <$> (word <* sep))
  <*> parseArgs <* sep
  <*> (PlainContent <$> textTill' anyChar (string "}}"))
 where
  sep = char '|'

-- | 'Parser' for 'ValRef'.
parseValRef :: Parser ValRef
parseValRef = ValRef . ValName <$>
  (string "{{E|" *> spaces *> textTill' (letter <|> digit) (spaces <* string "}}"))

-- | 'Parser' for 'Tem'.
parseTem :: Parser Tem
parseTem = parseNil <|> parseVal <|> parseRef <|> parseTxt
 where
  parseNil = Nil <$ endOfInput
  parseVal = Val <$> parsePlainValue <*> parseTem
  parseRef = Ref <$> parseValRef <*> parseTem
  parseTxt = Txt <$> textTill' anyChar (lookAhead (void parsePlainValue <|> void parseValRef) <|> endOfInput) <*> parseTem

-- | Bare minimum of serializing to and from 'Text' with no information of deserializing failure reason.
class Serialize a where
  encode :: a -> Text
  decode :: Text -> Maybe a

instance Serialize Args where
  encode (Args args) = commas (equals <$> Map.toList args)
    where
      commas :: [Text] -> Text = Text.intercalate ", "
      equals :: (ArgName, ArgValue) -> Text = \(ArgName n, ArgValue v) -> n `Text.append` " = " `Text.append` v
  decode = parseMaybe parseArgs

instance Serialize Tem where
  encode Nil = ""
  encode (Txt t template) = t `Text.append` encode template
  encode (Val (PlainValue valName algName args content) template) = Text.concat
    [ "{{P|"
    , unValName valName
    , "|"
    , unAlgName algName
    , "|"
    , encode args
    , "|"
    , unPlainContent content
    , "}}"
    , encode template
    ]
  encode (Ref (ValRef (ValName vn)) template) = Text.concat
    [ "{{E|"
    , vn
    , "}}"
    , encode template
    ]

  decode = parseMaybe parseTem
