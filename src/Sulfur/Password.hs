-- | Contraseñas aleatorias a partir de la fuente de entropía del sistema.
module Sulfur.Password
  ( generatePassword
  , passwordClasses
  ) where

import Crypto.Random (getRandomBytes)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.Text (Text)
import Data.Text qualified as T

-- | Sin espacios ni comillas, para que se pueda pegar en cualquier formulario.
-- 76 caracteres: unos 6.2 bits por carácter, 150 bits con la longitud default.
passwordClasses :: [String]
passwordClasses = [['a' .. 'z'], ['A' .. 'Z'], ['0' .. '9'], "-_.!@#$%^&*+=?"]

alphabet :: String
alphabet = concat passwordClasses

-- | Uniforme sobre el alfabeto: un byte que cae en la cola que no reparte
-- parejo entre los 76 caracteres se descarta (sin sesgo de módulo). Si el
-- resultado no trae al menos un carácter de cada clase se genera otro, lo que
-- sigue siendo uniforme sobre las contraseñas que sí las traen.
generatePassword :: Int -> IO Text
generatePassword len
  | len < length passwordClasses = ioError (userError "longitud menor que el número de clases de caracteres")
  | otherwise = do
      candidate <- go len []
      if all (any (`elem` candidate)) passwordClasses
        then pure (T.pack candidate)
        else generatePassword len
  where
    n = length alphabet
    limit = 256 - 256 `mod` n
    go 0 acc = pure acc
    go k acc = do
      bytes <- getRandomBytes k :: IO ByteString
      let picked = take k [alphabet !! (b `mod` n) | b <- map fromIntegral (BS.unpack bytes), b < limit]
      go (k - length picked) (acc ++ picked)
