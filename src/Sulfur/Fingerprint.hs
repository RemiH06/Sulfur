-- | Huella visual: color público y determinista derivado del nombre de una
-- entrada. No es secreta y nunca se deriva de la contraseña maestra ni de la
-- clave de la bóveda (ver CLAUDE.md, "Dos capas que nunca se mezclan").
module Sulfur.Fingerprint
  ( Oklch (..)
  , fingerprint
  , toSrgb
  , toHex
  , inGamut
  ) where

import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteArray qualified as BA
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Data.Text.Normalize (NormalizationMode (NFC), normalize)
import Data.Word (Word8)
import Text.Printf (printf)

-- | Color en OKLCH: luminosidad 0..1, croma 0..~0.4, matiz en grados.
data Oklch = Oklch
  { lightness :: Double
  , chroma :: Double
  , hue :: Double
  }
  deriving (Eq, Show)

-- | SHA-256 del texto (NFC, UTF-8) a OKLCH. NFC hace que una misma letra
-- escrita con o sin caracteres combinados dé el mismo color. La luminosidad se
-- limita a 0.45..0.85 para que nunca caiga en negro o blanco puros, y el croma
-- se recorta después lo justo para que el color exista en sRGB sin cambiar
-- luminosidad ni matiz.
fingerprint :: Text -> Oklch
fingerprint txt = fitGamut (Oklch l c h)
  where
    digest = BA.unpack (hash (encodeUtf8 (normalize NFC txt)) :: Digest SHA256)
    byte i = fromIntegral (digest !! i) :: Double
    h = (byte 0 * 256 + byte 1) / 65536 * 360
    l = 0.45 + byte 2 / 255 * 0.40
    c = 0.05 + byte 3 / 255 * 0.15

-- | Reduce el croma por bisección hasta quedar dentro de sRGB.
fitGamut :: Oklch -> Oklch
fitGamut color
  | inGamut color = color
  | otherwise = go 0 (chroma color) (20 :: Int)
  where
    go lo _ 0 = color {chroma = lo}
    go lo hi n
      | inGamut mid = go (chroma mid) hi (n - 1)
      | otherwise = go lo (chroma mid) (n - 1)
      where
        mid = color {chroma = (lo + hi) / 2}

inGamut :: Oklch -> Bool
inGamut color = all (\x -> x >= -eps && x <= 1 + eps) [r, g, b]
  where
    (r, g, b) = toLinearSrgb color
    eps = 1e-9

-- | OKLCH a sRGB lineal, con las matrices de Björn Ottosson.
toLinearSrgb :: Oklch -> (Double, Double, Double)
toLinearSrgb (Oklch l c h) = (r, g, b)
  where
    labA = c * cos (h * pi / 180)
    labB = c * sin (h * pi / 180)
    l' = (l + 0.3963377774 * labA + 0.2158037573 * labB) ^ (3 :: Int)
    m' = (l - 0.1055613458 * labA - 0.0638541728 * labB) ^ (3 :: Int)
    s' = (l - 0.0894841775 * labA - 1.2914855480 * labB) ^ (3 :: Int)
    r = 4.0767416621 * l' - 3.3077115913 * m' + 0.2309699292 * s'
    g = -1.2684380046 * l' + 2.6097574011 * m' - 0.3413193965 * s'
    b = -0.0041960863 * l' - 0.7034186147 * m' + 1.7076147010 * s'

-- | sRGB de 8 bits por canal.
toSrgb :: Oklch -> (Word8, Word8, Word8)
toSrgb color = (channel r, channel g, channel b)
  where
    (r, g, b) = toLinearSrgb color
    gammaEncode x
      | x <= 0.0031308 = 12.92 * x
      | otherwise = 1.055 * x ** (1 / 2.4) - 0.055
    channel x = round (255 * max 0 (min 1 (gammaEncode x)))

toHex :: Oklch -> String
toHex color = printf "#%02x%02x%02x" r g b
  where
    (r, g, b) = toSrgb color
