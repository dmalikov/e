{-# Language DeriveGeneric #-}
{-# Language StandaloneDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Tem where

import Control.DeepSeq
import Control.DeepSeq.Generics (genericRnf)
import GHC.Generics (Generic)

import E

deriving instance Generic PlainValue
deriving instance Generic ValName
deriving instance Generic AlgName
deriving instance Generic Args
deriving instance Generic ArgName
deriving instance Generic ArgValue
deriving instance Generic ValRef
deriving instance Generic PlainContent
deriving instance Generic Tem

instance NFData PlainValue   where rnf = genericRnf
instance NFData ValName      where rnf = genericRnf
instance NFData ValRef       where rnf = genericRnf
instance NFData AlgName      where rnf = genericRnf
instance NFData Args         where rnf = genericRnf
instance NFData ArgName      where rnf = genericRnf
instance NFData ArgValue     where rnf = genericRnf
instance NFData PlainContent where rnf = genericRnf
instance NFData Tem          where rnf = genericRnf
