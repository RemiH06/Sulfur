module Main (main) where

import Control.Exception (IOException, try)
import Control.Monad (unless)
import Data.Bits (complement)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Either (isLeft)
import Data.List (isInfixOf)
import Data.Text qualified as T
import Data.Text.Normalize (NormalizationMode (NFC, NFD), normalize)
import Sulfur.Fingerprint
import Sulfur.Import
import Sulfur.Password
import Sulfur.Vault
import System.Exit (exitFailure)
import System.IO (hSetEncoding, stdout, utf8)
import Test.QuickCheck

-- | Cualquier texto Unicode, no solo ASCII.
withText :: Testable p => (T.Text -> p) -> Property
withText p = forAll (T.pack . getUnicodeString <$> arbitrary) p

-- | Entrada con nombre no vacío, secreto cualquiera y, a veces, usuario y
-- categoría, todo Unicode.
withEntry :: Testable p => (Entry -> p) -> Property
withEntry = forAll $ do
  name <- T.pack . getUnicodeString <$> arbitrary `suchThat` (not . null . getUnicodeString)
  secret <- T.pack . getUnicodeString <$> arbitrary
  login <- fmap (T.pack . getUnicodeString) <$> arbitrary
  category <- fmap (T.pack . getUnicodeString) <$> arbitrary
  pure (Entry name secret login category)

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
  let other = newEntry (normalize NFC (entryName e) <> T.pack "-otra") (T.pack "intacto")
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
        pure $ entries k v1 === Right [normalizeEntry e]
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
  , ( "bóveda: el blob del índice no pasa por entrada"
    , once . ioProperty $ do
        (v, k) <- fresh
        pure $ entries k v {vaultEntries = [vaultIndex v]} === Left TamperedEntry
    )
  , ( "bóveda: alterar parámetros o sal del encabezado no abre"
    , once . ioProperty $ do
        (v, _) <- fresh
        let opensWith v' = either (=== WrongPassword) (const (property False)) (unlock (T.pack "maestra de prueba") v')
        pure $
          opensWith v {vaultKdf = KdfParams 1 32 1}
            .&&. opensWith v {vaultKdf = KdfParams 2 64 1}
            .&&. opensWith v {vaultSalt = flipByte 0 (vaultSalt v)}
    )
  , ( "bóveda: quitar o reordenar blobs a mano se detecta"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, _) <- withTwo e
        let tampered blobs = entries k v2 {vaultEntries = blobs}
        pure $
          tampered (drop 1 (vaultEntries v2)) === Left TamperedIndex
            .&&. tampered (reverse (vaultEntries v2)) === Left TamperedIndex
            .&&. tampered [] === Left TamperedIndex
    )
  , ( "bóveda: reinsertar un blob viejo (secreto anterior) se detecta"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, _) <- withTwo e
        v3 <- replaceSecret k (entryName e) (T.pack "nuevo") v2 >>= either (fail . show) pure
        let replayed = take 1 (vaultEntries v2) ++ drop 1 (vaultEntries v3)
        pure $ entries k v3 {vaultEntries = replayed} === Left TamperedIndex
    )
  , ( "bóveda: rechaza nombres duplicados, también con otra forma Unicode"
    , once . ioProperty $ do
        let e = newEntry (T.pack "\x00e9xito") (T.pack "uno")
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
        removed <- removeEntry k (entryName e) v2
        missing <- removeEntry k (T.pack "no existe") v2
        pure $
          (removed >>= entries k) === Right [other]
            .&&. (entries k <$> missing) === Left (EntryNotFound (T.pack "no existe"))
    )
  , ( "bóveda: editar cambia solo ese secreto"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, other) <- withTwo e
        r <- replaceSecret k (entryName e) (T.pack "nuevo") v2
        pure $ (r >>= entries k) === Right [(normalizeEntry e) {entrySecret = T.pack "nuevo"}, other]
    )
  , ( "bóveda: renombrar conserva el secreto y la otra entrada"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v2, other) <- withTwo e
        let new = entryName other <> T.pack "-nueva"
        renamed <- renameEntry k (entryName e) new v2
        toOther <- renameEntry k (entryName e) (entryName other) v2
        missing <- renameEntry k (T.pack "no existe") new v2
        pure $
          (renamed >>= entries k) === Right [(normalizeEntry e) {entryName = normalize NFC new}, other]
            .&&. (entries k <$> toOther) === Left (DuplicateName (entryName other))
            .&&. (entries k <$> missing) === Left (EntryNotFound (T.pack "no existe"))
    )
  , ( "bóveda: usuario y categoría se cambian y se borran sin tocar el secreto"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v1) <- withOne e
        let name = entryName e
            step r f = either (pure . Left) f r
        r <-
          step (Right v1) (setLogin k name (Just (T.pack "  hex@correo.mx ")))
            >>= (`step` setCategory k name (Just (T.pack "Trabajo")))
        cleared <- step r (setLogin k name (Just (T.pack "   "))) >>= (`step` setCategory k name Nothing)
        let base = normalizeEntry e
        pure $
          (r >>= entries k) === Right [base {entryLogin = Just (T.pack "hex@correo.mx"), entryCategory = Just (T.pack "Trabajo")}]
            .&&. (cleared >>= entries k) === Right [base {entryLogin = Nothing, entryCategory = Nothing}]
    )
  , ( "categoría: el filtro ignora mayúsculas, espacios y forma Unicode"
    , once $
        let conCategoria c = (newEntry (T.pack "x") (T.pack "y")) {entryCategory = Just (T.pack c)}
         in inCategory (T.pack "  TRABAJO ") (conCategoria "trabajo")
              -- \& corta el escape: sin él, \x0301a se leería como U+301A.
              .&&. inCategory (T.pack "Categori\x0301\&a") (conCategoria "Categor\x00ed\&a")
              .&&. not (inCategory (T.pack "trabajo") (conCategoria "personal"))
              .&&. not (inCategory (T.pack "trabajo") (newEntry (T.pack "x") (T.pack "y")))
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
  , ( "relleno: ida y vuelta, múltiplo de 256 y siempre agrega algo"
    , forAll (BS.pack <$> arbitrary) $ \b ->
        unpad (pad b) === Just b
          .&&. BS.length (pad b) `mod` 256 === 0
          .&&. BS.length (pad b) > BS.length b
    )
  , ( "relleno: rechaza lo que no termina en 0x80 y ceros"
    , once $ map unpad [BS.empty, BS.replicate 256 0, BS.pack [0x41, 0x81, 0]] === [Nothing, Nothing, Nothing]
    )
  , ( "bóveda: entradas cortas y largas miden lo mismo en disco"
    , once . ioProperty $ do
        (v, k) <- fresh
        r <- addEntries k [newEntry (T.pack "a") (T.pack "x"), newEntry (T.pack "un nombre más largo") (T.replicate 150 (T.pack "y"))] v
        pure $ case r of
          Left err -> counterexample (show err) False
          Right v1 -> case map BS.length (vaultEntries v1) of
            [l1, l2] -> l1 === l2
            ls -> counterexample (show ls) False
    )
  , ( "bóveda: importar es todo o nada ante nombres repetidos"
    , withEntry $ \e -> ioProperty $ do
        (_, k, v1) <- withOne e
        let nueva = newEntry (normalize NFC (entryName e) <> T.pack "-nueva") (T.pack "z")
        contraExistente <- addEntries k [nueva, e] v1
        dentroDeLista <- addEntries k [nueva, nueva] v1
        pure $
          (entries k <$> contraExistente) === Left (DuplicateName (normalize NFC (entryName e)))
            .&&. (entries k <$> dentroDeLista) === Left (DuplicateName (entryName nueva))
    )
  , ( "import: lee nombre=secreto con BOM, CRLF, comentarios y = en el secreto"
    , once $
        parseEntries (T.pack "\xfeffGmail personal=abc=def\r\n# comentario\r\n\r\n  banco = con espacios \r\n")
          === Right [newEntry (T.pack "Gmail personal") (T.pack "abc=def"), newEntry (T.pack "banco") (T.pack " con espacios ")]
    )
  , ( "import: # solo es comentario al inicio de la línea, no dentro del secreto"
    , once $
        parseEntries (T.pack "user=#password\n  # comentario con espacios\nfiltro=a#b\n")
          === Right [newEntry (T.pack "user") (T.pack "#password"), newEntry (T.pack "filtro") (T.pack "a#b")]
    )
  , ( "import: los encabezados [categoría | usuario] aplican hasta el siguiente"
    , once $
        parseEntries
          ( T.pack $
              unlines
                [ "[personal | hex@gmail.com]"
                , "Gmail=a"
                , "[trabajo]"
                , "Slack=b"
                , "[ | otro@correo.mx ]"
                , "X=c"
                , "[]"
                , "Y=d"
                , "[x=y]"
                ]
          )
          === Right
            [ Entry (T.pack "Gmail") (T.pack "a") (Just (T.pack "hex@gmail.com")) (Just (T.pack "personal"))
            , Entry (T.pack "Slack") (T.pack "b") Nothing (Just (T.pack "trabajo"))
            , Entry (T.pack "X") (T.pack "c") (Just (T.pack "otro@correo.mx")) Nothing
            , newEntry (T.pack "Y") (T.pack "d")
            , newEntry (T.pack "[x") (T.pack "y]")
            ]
    )
  , ( "import: reporta cada línea mala sin repetir secretos"
    , once $ case parseEntries (T.pack "sin igual\n=huerfano\nvacio=\ncomillas=\"s3cr3t0\"\nbien=ok\n") of
        Right es -> counterexample (show es) False
        Left errs ->
          length errs === 4
            .&&. map (takeWhile (/= ':')) errs === ["línea 1", "línea 2", "línea 3", "línea 4"]
            .&&. not (any (\m -> "s3cr3t0" `isInfixOf` m || "huerfano" `isInfixOf` m) errs)
    )
  , ( "import: cualquier secreto de una línea se lee literal"
    , forAll (T.pack . getUnicodeString <$> arbitrary) $ \s ->
        let quoted = T.length s >= 2 && T.head s `elem` ['"', '\''] && T.head s == T.last s
         in not (T.null s) && not (T.any (`elem` ['\n', '\r']) s) && not quoted ==>
              parseEntries (T.pack "x=" <> s) === Right [newEntry (T.pack "x") s]
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
