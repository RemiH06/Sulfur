-- | Secretos (la maestra y el secreto de cada entrada) en memoria que se borra
-- al liberarse ('ScrubbedBytes'), en UTF-8. Un 'Text' o un 'String' quedan en
-- el montículo de GHC hasta que el recolector los sobrescribe, sin fecha; por
-- eso un secreto nunca se vuelve uno de ellos dentro de Sulfur.
module Sulfur.Secret
  ( Secret
  , secretFromText
  , secretFromUtf8
  , secretBytes
  , secretLength
  , nullSecret
  , normalizeSecret
  ) where

import Data.Bits ((.&.))
import Data.ByteArray (ScrubbedBytes)
import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Unsafe (unsafePackCStringLen)
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Text.Normalize (NormalizationMode (NFC), normalize)
import System.IO.Unsafe (unsafeDupablePerformIO)

newtype Secret = Secret ScrubbedBytes

-- | En tiempo constante, para que comparar no delate cuántos bytes coinciden.
instance Eq Secret where
  Secret a == Secret b = BA.constEq a b

-- | Nunca el contenido: así un `show` o un error no lo imprimen por accidente.
instance Show Secret where
  show _ = "<secreto>"

-- | Pasa por la memoria del 'Text' de origen, que no se borra. Solo para
-- pruebas e importación, donde el secreto ya venía en claro.
secretFromText :: Text -> Secret
secretFromText = Secret . BA.convert . encodeUtf8

-- | 'Nothing' si no es UTF-8 válido.
secretFromUtf8 :: ScrubbedBytes -> Maybe Secret
secretFromUtf8 b
  | onView b BS.isValidUtf8 = Just (Secret b)
  | otherwise = Nothing

secretBytes :: Secret -> ScrubbedBytes
secretBytes (Secret b) = b

-- | En caracteres (puntos de código), no en bytes: cuenta los bytes que no
-- son de continuación.
secretLength :: Secret -> Int
secretLength (Secret b) = length [() | i <- [0 .. BA.length b - 1], BA.index b i .&. 0xC0 /= 0x80]

nullSecret :: Secret -> Bool
nullSecret (Secret b) = BA.null b

-- | A NFC, como la huella. El texto ASCII ya está en NFC y se devuelve tal
-- cual; cualquier otro pasa una vez por 'Text', porque `unicode-transforms`
-- solo normaliza 'Text'.
normalizeSecret :: Secret -> Secret
normalizeSecret s@(Secret b)
  | BA.all (< 0x80) b = s
  | otherwise = Secret (BA.convert (encodeUtf8 (normalize NFC (onView b decodeUtf8))))

-- | Aplica una función de 'BS.ByteString' sobre la memoria del secreto sin
-- copiarla. El resultado se evalúa antes de soltar el puntero.
onView :: ScrubbedBytes -> (BS.ByteString -> a) -> a
onView b f = unsafeDupablePerformIO $
  BA.withByteArray b $ \p -> do
    view <- unsafePackCStringLen (p, BA.length b)
    pure $! f view
