# Sulfur

Gestor de contraseñas de línea de comandos que además convierte texto en color de forma determinista: mismo texto, mismo color. Nombre fijo.

## Estado

- `legacy/kotlin/Sulfur.kt` es la versión 1.0 en Kotlin, un experimento sin valor de seguridad. No se extiende. Sirve solo como referencia de lo que ya existe.
- Versión 2 en **Haskell**, en uso real desde el 4 de octubre de 2026: la bóveda del usuario se llama `azufre` (`SULFUR_VAULT` de usuario apunta a `%APPDATA%\sulfur\azufre.json`) y el ejecutable está instalado en `%USERPROFILE%\.local\bin`. Tras cambiar el código, reinstalar con `cabal install exe:sulfur --installdir=C:\Users\hecto\.local\bin --install-method=copy --overwrite-policy=always`. Nunca tocar ni leer la bóveda real; las pruebas usan bóvedas temporales en el scratchpad.

## Dos capas que nunca se mezclan

1. **Huella visual (pública).** Color derivado del nombre de una entrada. No es secreta y no protege nada. Sirve para reconocer entradas de un vistazo. Se decidió no hacer imagen: un mosaico de colores sería tan sensible como la lista de nombres.
2. **Bóveda (secreta).** Cifrado real: clave derivada de la contraseña maestra con Argon2id o scrypt (sal aleatoria), y cifrado autenticado (XChaCha20-Poly1305 o secretbox de libsodium) con nonce aleatorio por cada entrada.

Reglas de seguridad:
- Nunca implementar criptografía propia. Usar bibliotecas revisadas.
- Nunca guardar la maestra ni el texto plano en disco, logs ni salida.
- La huella visual no se deriva de la clave ni de la maestra, solo del nombre de la entrada, para que no sea un canal de filtración.
- Revisión externa antes de usarlo con contraseñas reales.

## Principios (skills globales)

- Filtro `ponytail` antes de cada dependencia o función nueva: ¿stdlib?, ¿ya instalada?, ¿una línea? Sin recortar validación, errores, seguridad ni accesibilidad.
- Colores: `colorimetria` para paletas y contraste WCAG. Nada de `#000` ni `#fff` puros.
- UI con íconos y sin texto de respaldo (si hay interfaz).
- Redacción en español mexicano, sin guión largo (`redaccion-espanol-mx`).
- Commits de una línea, conventional (`commit-checkpoints`). No commitear sin pedirlo.

## Plan Haskell

- Build con cabal (`sulfur.cabal`), toolchain vía GHCup en `C:\ghcup`. Dependencias fijadas en `cabal.project.freeze` (incluye `base`, así que exige GHC 9.10.3); para actualizarlas, `cabal freeze --enable-tests` a propósito.
- Huella (`src/Sulfur/Fingerprint.hs`), **congelada**: texto normalizado a NFC (`unicode-transforms`), en UTF-8, a SHA-256, a color OKLCH con luminosidad 0.45..0.85 y croma recortado a sRGB. Cambiarla cambia todos los colores ya memorizados; la prueba "valor de referencia" lo detecta.
- Bóveda (`src/Sulfur/Vault.hs`): archivo JSON (`aeson`). Clave con Argon2id (RFC 9106: 3 pasadas, 64 MiB, 4 carriles; los parámetros viven en el archivo y se acotan al leer). Cada entrada se sella completa (nombre, secreto y, opcionales, usuario y categoría) con XChaCha20-Poly1305 y nonce aleatorio propio, así que en disco no se ven nombres, correos ni categorías; `normalizeEntry` limpia todo antes de sellar (categoría siempre en minúsculas, por convención del usuario). Formato versión 3: texto plano de cada entrada rellenado a múltiplos de 256 bytes (ISO/IEC 7816-4) antes de sellar, y un índice sellado con el SHA-256 de cada blob en orden confirma la maestra aunque no haya entradas y detecta entradas borradas, reordenadas o reinsertadas desde una versión vieja; toda mutación pasa por `withBlobs`, que lo vuelve a sellar. AAD distinto para índice y entradas. La huella nunca se guarda en disco: es un hash sin sal del nombre y lo delataría.
- Maestra y nombres se normalizan a NFC. Guardado atómico (temporal + renombrar).
- `crypton` para las dos capas. Se descartó `saltine` porque exige la librería C de libsodium, incómoda en Windows.
- CLI (`app/Main.hs`): `color`, `init`, `add`, `gen` (genera o reemplaza con confirmación), `copy` (portapapeles 30 s con los formatos `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0` y `CanUploadToCloudClipboard=0`; vacía solo si el número de secuencia no cambió; `app/Clipboard.hs`, solo Windows), `get` (solo a una terminal real), `edit`, `mv`, `rm` (con confirmación), `list [categoría]` (agrupa y filtra con `inCategory`), `set` (usuario o categoría; `add` y `gen` los preguntan al crear), `passwd` (sal, verificación y Argon2 nuevos; vuelve a sellar todo), `import` (archivo `nombre=secreto` con encabezados `[categoría | usuario]`, parser en `src/Sulfur/Import.hs`; todo o nada vía `addEntries`; errores sin repetir secretos; ofrece borrar el archivo). Búsqueda sin nombre exacto (`src/Sulfur/Search.hs`, `matchEntries`: exacto, luego sin mayúsculas ni acentos, luego contenido; varias candidatas se eligen por número) en `copy`, `get`, `edit`, `set`, `rm` y el nombre viejo de `mv`, nunca en `add` ni `gen`. El `.gitignore` excluye `.env`, `*.env` y `.env.*`. Generador en `src/Sulfur/Password.hs`: 76 caracteres sin sesgo de módulo, al menos uno de cada clase, 24 por default. Entrada con `haskeline` sin historial solo si stdin es consola real; si no (pipe, Git Bash) se lee como UTF-8 y sin `\r`, porque haskeline decodificaría con la página de códigos del sistema y una maestra con "ñ" daría otra clave. Bóveda en `%APPDATA%\sulfur\vault.json` o donde diga `SULFUR_VAULT`. En Windows cambia la consola a UTF-8 mientras corre y la restaura al salir.
- Pruebas con QuickCheck en `test/Spec.hs`: huella (gamut, rango, NFC, valor de referencia) y bóveda (ida y vuelta, maestra equivocada, nonces distintos, cualquier byte alterado, duplicados, JSON, parámetros abusivos).
- `docs/index.html`: página de GitHub Pages (servida desde `/docs` de `main`), tema sherry de iroFactory con paleta propia (Kawah Ijen: `--sulfur`, `--flame`, `--lake`, `--ember`, `--molten`, verificada AA en ambos modos). Reglas de iroFactory: un solo archivo, Bunny Fonts, sin `#000`/`#fff`, punto medio en vez de guion largo. Las salidas de consola son reales, de una bóveda de demostración con datos inventados (dominios `example.com`); al cambiar un comando, volver a correrlo y copiar la salida, no inventarla. La huella en JavaScript es un port de `Fingerprint.hs` verificado contra el ejecutable (300 textos, 0 diferencias): si cambia uno, cambia el otro. Pixel Card y la retícula de triángulos vienen de sherry, con la licencia de React Bits en el encabezado.
- `docs/modelo-de-amenazas.md`: documento para la revisión externa. Mantenerlo al día cuando cambie el diseño criptográfico o el formato.
- Interfaz web después, si se decide.

## Decisiones pendientes

- En Git Bash (mintty) la salida no cuenta como terminal, así que `get` se niega; en PowerShell, cmd y la terminal de VS Code sí funciona.
- Reversión completa sin detectar: el índice atrapa entradas borradas, reordenadas o reinsertadas, pero restaurar el archivo entero a una versión vieja sigue siendo válido. Arreglarlo requiere un contador guardado fuera del archivo (si se pierde, la bóveda queda bloqueada).
- Los `Text` con secretos no se borran de memoria al liberarse (limitación del GC de Haskell); solo la clave derivada vive en memoria que se borra.
- Respaldos automáticos antes de cada cambio: se pospone hasta que exista Bakery. Ojo: un respaldo sigue abriendo con la maestra vieja después de `passwd`.
- Si la huella se muestra en la bóveda de Obsidian o solo en el CLI; de eso depende contra qué fondo medir su contraste.
