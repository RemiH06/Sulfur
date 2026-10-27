-- | Contraseñas aleatorias a partir de la fuente de entropía del sistema.
module Sulfur.Password
  ( generatePassword
  , passwordClasses
  ) where

import Control.Monad (foldM)
import Crypto.Random (getRandomBytes)
import Data.ByteArray (ScrubbedBytes)
import Data.ByteArray qualified as BA
import Data.Char (ord)
import Data.Maybe (fromMaybe)
import Data.Word (Word8)
import Foreign.Ptr (Ptr)
import Foreign.Storable (pokeByteOff)
import Sulfur.Secret (Secret, secretFromUtf8)

-- | Sin espacios ni comillas, para que se pueda pegar en cualquier formulario.
-- 76 caracteres: unos 6.2 bits por carácter, 150 bits con la longitud default.
passwordClasses :: [String]
passwordClasses = [['a' .. 'z'], ['A' .. 'Z'], ['0' .. '9'], "-_.!@#$%^&*+=?"]

alphabet :: [Word8]
alphabet = map (fromIntegral . ord) (concat passwordClasses)

-- | Uniforme sobre el alfabeto: un byte que cae en la cola que no reparte
-- parejo entre los 76 caracteres se descarta (sin sesgo de módulo). Si el
-- resultado no trae al menos un carácter de cada clase se genera otro, lo que
-- sigue siendo uniforme sobre las contraseñas que sí las traen. Los bytes
-- aleatorios y la contraseña viven en 'ScrubbedBytes': de los aleatorios se
-- deduce la contraseña, así que tampoco pasan por una lista.
generatePassword :: Int -> IO Secret
generatePassword len
  | len < length passwordClasses = ioError (userError "longitud menor que el número de clases de caracteres")
  | otherwise = do
      candidate <- BA.alloc len fill :: IO ScrubbedBytes
      if all (\cls -> BA.any (`elem` map (fromIntegral . ord) cls) candidate) passwordClasses
        then pure (fromMaybe (error "el alfabeto es ASCII") (secretFromUtf8 candidate))
        else generatePassword len
  where
    n = length alphabet
    limit = 256 - 256 `mod` n
    -- Pide tantos bytes como faltan; como cada uno da a lo más un carácter,
    -- nunca se escribe de más.
    fill :: Ptr Word8 -> IO ()
    fill dst = go 0
      where
        go k
          | k >= len = pure ()
          | otherwise = do
              bytes <- getRandomBytes (len - k) :: IO ScrubbedBytes
              go =<< foldM (place bytes) k [0 .. BA.length bytes - 1]
        place bytes j i
          | b < limit = pokeByteOff dst j (alphabet !! (b `mod` n)) >> pure (j + 1)
          | otherwise = pure j
          where
            b = fromIntegral (BA.index bytes i)
