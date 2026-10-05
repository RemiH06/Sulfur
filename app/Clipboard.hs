{-# LANGUAGE CPP #-}

-- | Copiar un secreto al portapapeles de Windows sin que entre al historial
-- (Win+V) ni al portapapeles en la nube, y vaciarlo al terminar el plazo.
module Clipboard (copyTransient) where

import Data.Text (Text)
#if defined(mingw32_HOST_OS)
import Control.Concurrent (threadDelay)
import Control.Exception (finally, onException)
import Control.Monad (unless, when)
import Data.Text qualified as T
import Data.Word (Word16, Word32, Word8)
import Foreign.C.String (withCWStringLen)
import Foreign.Marshal.Utils (copyBytes)
import Foreign.Ptr (Ptr, castPtr, nullPtr, plusPtr)
import Foreign.Storable (poke)
import Graphics.Win32.GDI.Clip (ClipboardFormat, cF_UNICODETEXT, closeClipboard, emptyClipboard, registerClipboardFormat)
import System.Win32.Mem (gMEM_MOVEABLE, globalAlloc, globalLock)
import System.Win32.Types (BOOL, DWORD, HANDLE)
#else
import System.Exit (die)
#endif

-- | Copia, espera el plazo y, al terminar o con Ctrl+C, vacía el portapapeles
-- solo si sigue teniendo lo que se copió aquí, para no borrar algo que el
-- usuario haya copiado después. 'False' si otro contenido ya lo reemplazó.
copyTransient :: Int -> Text -> IO Bool
#if defined(mingw32_HOST_OS)
copyTransient seconds secret = do
  withClipboard $ do
    emptyClipboard
    setData cF_UNICODETEXT =<< unicodeBlob secret
    -- Formatos que Windows respeta para no guardar el contenido en el
    -- historial ni subirlo a la nube; los usan los gestores de contraseñas.
    mapM_
      (\name -> do fmt <- registerClipboardFormat name; setData fmt =<< dwordBlob 0)
      ["ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"]
  ours <- c_GetClipboardSequenceNumber
  let clearIfOurs = do
        now <- c_GetClipboardSequenceNumber
        when (now == ours) $ withClipboard emptyClipboard
        pure (now == ours)
  threadDelay (seconds * 1000000) `onException` clearIfOurs
  clearIfOurs

-- | Otro programa puede tener el portapapeles abierto un instante; se
-- reintenta antes de rendirse.
withClipboard :: IO a -> IO a
withClipboard action = open (20 :: Int) >> (action `finally` closeClipboard)
  where
    open n = do
      ok <- c_OpenClipboard nullPtr
      unless ok $
        if n <= 1
          then ioError (userError "el portapapeles está ocupado por otro programa")
          else threadDelay 50000 >> open (n - 1)

-- | Memoria global llenada por la función dada. Si SetClipboardData la acepta,
-- el sistema se queda con ella; si no, se libera aquí.
blob :: Int -> (Ptr Word8 -> IO ()) -> IO HANDLE
blob size fill = do
  mem <- globalAlloc gMEM_MOVEABLE (fromIntegral size)
  ptr <- globalLock mem
  fill (castPtr ptr)
  _ <- c_GlobalUnlock mem
  pure mem

-- | UTF-16 con terminador nulo, como lo pide CF_UNICODETEXT.
unicodeBlob :: Text -> IO HANDLE
unicodeBlob t = withCWStringLen (T.unpack t) $ \(src, len) ->
  blob ((len + 1) * 2) $ \dst -> do
    copyBytes dst (castPtr src) (len * 2)
    poke (dst `plusPtr` (len * 2)) (0 :: Word16)

dwordBlob :: Word32 -> IO HANDLE
dwordBlob v = blob 4 (\dst -> poke (castPtr dst) v)

setData :: ClipboardFormat -> HANDLE -> IO ()
setData fmt mem = do
  r <- c_SetClipboardData fmt mem
  when (r == nullPtr) $ do
    _ <- c_GlobalFree mem
    ioError (userError "no se pudo escribir en el portapapeles")

-- GlobalUnlock devuelve FALSE al llegar a cero bloqueos (el caso normal), y la
-- versión del paquete Win32 lo trata como error; por eso estas van directo.
foreign import ccall unsafe "windows.h OpenClipboard" c_OpenClipboard :: HANDLE -> IO BOOL
foreign import ccall unsafe "windows.h SetClipboardData" c_SetClipboardData :: ClipboardFormat -> HANDLE -> IO HANDLE
foreign import ccall unsafe "windows.h GlobalUnlock" c_GlobalUnlock :: HANDLE -> IO BOOL
foreign import ccall unsafe "windows.h GlobalFree" c_GlobalFree :: HANDLE -> IO HANDLE
foreign import ccall unsafe "windows.h GetClipboardSequenceNumber" c_GetClipboardSequenceNumber :: IO DWORD
#else
copyTransient _ _ = die "copy por ahora solo funciona en Windows." >> pure False
#endif
