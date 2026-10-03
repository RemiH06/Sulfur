module Main (main) where

import Data.Text qualified as T
import Sulfur.Fingerprint
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO
import Text.Printf (printf)

main :: IO ()
main = do
  mapM_ (`hSetEncoding` utf8) [stdout, stderr]
  args <- getArgs
  case args of
    [name] -> do
      let color = fingerprint (T.pack name)
          (r, g, b) = toSrgb color
      tty <- hIsTerminalDevice stdout
      -- Muestra de color en terminales con truecolor; se omite al redirigir.
      let swatch = if tty then printf "\ESC[48;2;%d;%d;%dm    \ESC[0m " r g b else ""
      printf "%s%s  oklch(%.3f %.3f %.1f)\n" (swatch :: String) (toHex color)
        (lightness color) (chroma color) (hue color)
    _ -> do
      hPutStrLn stderr "Uso: sulfur \"<nombre de la entrada>\""
      exitFailure
