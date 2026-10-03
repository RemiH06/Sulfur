module Main (main) where

import Control.Monad (unless)
import Data.Text qualified as T
import Data.Text.Normalize (NormalizationMode (NFC, NFD), normalize)
import Sulfur.Fingerprint
import System.Exit (exitFailure)
import Test.QuickCheck

-- | Cualquier texto Unicode, no solo ASCII.
withText :: Testable p => (T.Text -> p) -> Property
withText p = forAll (T.pack . getUnicodeString <$> arbitrary) p

properties :: [(String, Property)]
properties =
  [ ("cae dentro de sRGB", withText (inGamut . fingerprint))
  , ( "luminosidad en 0.45..0.85"
    , withText $ \t -> let l = lightness (fingerprint t) in l >= 0.45 && l <= 0.85
    )
  , ( "nunca negro ni blanco puros"
    , withText $ \t -> toHex (fingerprint t) `notElem` ["#000000", "#ffffff"]
    )
  , ( "hex de 7 caracteres"
    , withText $ \t -> let h = toHex (fingerprint t) in length h == 7 && take 1 h == "#"
    )
  , ( "mismo color con o sin caracteres combinados"
    , withText $ \t -> fingerprint (normalize NFD t) === fingerprint (normalize NFC t)
    )
    -- Si esto falla, el algoritmo cambió y todos los colores conocidos con él.
    -- "éxito" va dos veces: con é precompuesta (U+00E9) y con e + acento (U+0301).
  , ( "valor de referencia"
    , once $
        map (toHex . fingerprint . T.pack) ["Fry", "日本語", "\x00e9xito", "e\x0301xito"]
          === ["#3fa5d8", "#006a4f", "#9472a8", "#9472a8"]
    )
  ]

main :: IO ()
main = do
  results <- mapM (\(name, p) -> putStrLn name >> quickCheckResult p) properties
  unless (all isSuccess results) exitFailure
