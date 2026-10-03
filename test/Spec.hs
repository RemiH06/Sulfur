module Main (main) where

import Control.Exception (IOException, try)
import Control.Monad (unless)
import Data.Bits (complement)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Either (isLeft)
import Data.Text qualified as T
import Data.Text.Normalize (NormalizationMode (NFC, NFD), normalize)
import Sulfur.Fingerprint
import Sulfur.Password
import Sulfur.Vault
import System.Exit (exitFailure)
import System.IO (hSetEncoding, stdout, utf8)
import Test.QuickCheck

-- | Cualquier texto Unicode, no solo ASCII.
withText :: Testable p => (T.Text -> p) -> Property
withText p = forAll (T.pack . getUnicodeString <$> arbitrary) p

-- | Entrada con nombre no vacío y secreto cualquiera, ambos Unicode.
withEntry :: Testable p => (Entry -> p) -> Property
withEntry = forAll $ do
  name <- T.pack . getUnicodeString <$> arbitrary `suchThat` (not . null . getUnicodeString)
  Entry name . T.pack . getUnicodeString <$> arbitrary

-- | Argon2 al mínimo para que las pruebas no tarden; la seguridad de los
-- parámetros reales no es lo que se prueba aquí.
fresh :: IO (Vault, MasterKey)
fresh = newVault (KdfParams 1 64 1) (T.pack "maestra de prueba") >>= either (fail . show) pure

-- | Bóveda nueva con una entrada.
withOne :: Entry -> IO (Vault, MasterKey, Vault)
withOne e = do
  (v, k) <- fresh
  v1 <- addEntry k e v >>= either (fail . show) pure
  pure (v, k, v1)

-- | Bóveda con la entrada dada más otra de nombre distinto, que es la que
-- debe quedar intacta.
withTwo :: Entry -> IO (Vault, MasterKey, Vault, Entry)
withTwo e = do
  (v, k, v1) <- withOne e
  let other = Entry (normalize NFC (entryName e) <> T.pack "-otra") (T.pack "intacto")
  v2 <- addEntry k other v1 >>= either (fail . show) pure
  pure (v, k, v2, other)

flipByte :: Int -> BS.ByteString -> BS.ByteString
flipByte i b = let (pre, post) = BS.splitAt (i `mod` BS.length b) b in pre <> BS.map complement (BS.take 1 post) <> BS.drop 1 post

properties :: [(String, Property)]
properties =
  [ ("cae dentro de sRGB", withText (inGamut . fingerprint))
  , ( "luminosidad en 0.45..0.85"
    , -- Tolerancia de redondeo: 0.45 + 0.40 da 0.8500000000000001 en Double.
      withText $ \t -> let l = lightness (fingerprint t) in l >= 0.45 - 1e-12 && l <= 0.85 + 1e-12
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
  , ( "bóveda: descifra lo que cifra, con el nombre en NFC"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v1) <- withOne e
        pure $ entries k v1 === Right [e {entryName = normalize NFC (entryName e)}]
    )
  , ( "bóveda: la maestra correcta abre y otra no"
    , once . ioProperty $ do
        (v, _) <- fresh
        pure $
          either (const False) (const True) (unlock (T.pack "maestra de prueba") v)
            .&&. either (=== WrongPassword) (const (property False)) (unlock (T.pack "maestra de prueba ") v)
    )
  , ( "bóveda: mismo contenido y misma clave dan cifrados distintos"
    , withEntry $ \e -> ioProperty $ do
        (v, k, v1) <- withOne e
        v2 <- addEntry k e v >>= either (fail . show) pure
        pure $ vaultEntries v1 =/= vaultEntries v2
    )
  , ( "bóveda: cualquier byte alterado se detecta"
    , withEntry $ \e -> forAll arbitrary $ \(NonNegative i) -> ioProperty $ do
        (_, k, v1) <- withOne e
        pure $ entries k v1 {vaultEntries = map (flipByte i) (vaultEntries v1)} === Left TamperedEntry
    )
  , ( "bóveda: el blob de verificación no pasa por entrada"
    , once . ioProperty $ do
        (v, k) <- fresh
        pure $ entries k v {vaultEntries = [vaultCheck v]} === Left TamperedEntry
    )
  , ( "bóveda: rechaza nombres duplicados, también con otra forma Unicode"
    , once . ioProperty $ do
        let e = Entry (T.pack "\x00e9xito") (T.pack "uno")
        (_, k, v1) <- withOne e
        r <- addEntry k e {entryName = T.pack "e\x0301xito"} v1
        pure $ r === Left (DuplicateName (T.pack "\x00e9xito"))
    )
  , ( "bóveda: JSON ida y vuelta"
    , withEntry $ \e -> ioProperty $ do
        (_, _, v1) <- withOne e
        pure $ decodeVault (LBS.toStrict (encodeVault v1)) === Right v1
    )
  , ( "bóveda: rechaza parámetros de Argon2 abusivos al leer"
    , once . ioProperty $ do
        (v, _) <- fresh
        let reread kdf = decodeVault (LBS.toStrict (encodeVault v {vaultKdf = kdf}))
        pure $ conjoin (map (isLeft . reread) [KdfParams 1 99999999 1, KdfParams 0 64 1, KdfParams 1 64 99])
    )
  , ( "bóveda: borrar quita solo esa entrada"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, other) <- withTwo e
        pure $
          (removeEntry k (entryName e) v2 >>= entries k) === Right [other]
            .&&. (entries k <$> removeEntry k (T.pack "no existe") v2) === Left (EntryNotFound (T.pack "no existe"))
    )
  , ( "bóveda: editar cambia solo ese secreto"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, other) <- withTwo e
        r <- replaceSecret k (entryName e) (T.pack "nuevo") v2
        pure $ (r >>= entries k) === Right [Entry (normalize NFC (entryName e)) (T.pack "nuevo"), other]
    )
  , ( "bóveda: renombrar conserva el secreto y la otra entrada"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, other) <- withTwo e
        let new = entryName other <> T.pack "-nueva"
        renamed <- renameEntry k (entryName e) new v2
        toOther <- renameEntry k (entryName e) (entryName other) v2
        missing <- renameEntry k (T.pack "no existe") new v2
        pure $
          (renamed >>= entries k) === Right [Entry (normalize NFC new) (entrySecret e), other]
            .&&. (entries k <$> toOther) === Left (DuplicateName (entryName other))
            .&&. (entries k <$> missing) === Left (EntryNotFound (T.pack "no existe"))
    )
  , ( "bóveda: cambiar la maestra conserva las entradas y retira la anterior"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, _) <- withTwo e
        changed <- changeMaster k (KdfParams 1 64 1) (T.pack "maestra nueva de prueba") v2
        pure $ case changed of
          Left err -> counterexample (show err) False
          Right (v', k') ->
            entries k' v' === entries k v2
              .&&. either (=== WrongPassword) (const (property False)) (unlock (T.pack "maestra de prueba") v')
              .&&. either (const False) (const True) (unlock (T.pack "maestra nueva de prueba") v')
    )
  , ( "contraseña generada: longitud, alfabeto y todas las clases"
    , forAll (choose (12, 128)) $ \n -> ioProperty $ do
        p <- T.unpack <$> generatePassword n
        pure $
          length p === n
            .&&. all (`elem` concat passwordClasses) p
            .&&. all (any (`elem` p)) passwordClasses
    )
  , ( "contraseña generada: rechaza longitudes imposibles"
    , once . ioProperty $ do
        r <- try (generatePassword 3) :: IO (Either IOException T.Text)
        pure (isLeft r)
    )
  ]

main :: IO ()
main = do
  hSetEncoding stdout utf8
  results <- mapM (\(name, p) -> putStrLn name >> quickCheckResult p) properties
  unless (all isSuccess results) exitFailure
