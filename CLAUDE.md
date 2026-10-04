# Sulfur

Convierte texto en colores e imágenes de forma determinista: mismo texto, mismo resultado. Nombre fijo. Objetivo a futuro: que funcione como gestor de contraseñas.

## Estado

- `legacy/kotlin/Sulfur.kt` es la versión 1.0 en Kotlin, un experimento sin valor de seguridad. No se extiende. Sirve solo como referencia de lo que ya existe.
- En marcha: rework completo en **Haskell**, mismo concepto (texto a color/imagen), sin la matemática de Euler ni Fibonacci.

## Dos capas que nunca se mezclan

1. **Huella visual (pública).** Color o imagen derivados de un texto. No es secreta y no protege nada. Sirve para reconocer entradas de un vistazo. Puede ser un degradado, un sólido o un patrón.
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
- Huella (`src/Sulfur/Fingerprint.hs`), **congelada**: texto normalizado a NFC (`unicode-transforms`), en UTF-8, a SHA-256, a color OKLCH con luminosidad 0.45..0.85 y croma recortado a sRGB. Cambiarla cambia todos los colores ya memorizados; la prueba "valor de referencia" lo detecta. Imagen después (PNG vía JuicyPixels).
- Bóveda (`src/Sulfur/Vault.hs`): archivo JSON (`aeson`). Clave con Argon2id (RFC 9106: 3 pasadas, 64 MiB, 4 carriles; los parámetros viven en el archivo y se acotan al leer). Cada entrada sella nombre y secreto juntos con XChaCha20-Poly1305 y nonce aleatorio propio, así que los nombres no se ven en disco. Formato versión 2: un índice sellado con el SHA-256 de cada blob en orden confirma la maestra aunque no haya entradas y detecta entradas borradas, reordenadas o reinsertadas desde una versión vieja; toda mutación pasa por `withBlobs`, que lo vuelve a sellar. AAD distinto para índice y entradas. La huella nunca se guarda en disco: es un hash sin sal del nombre y lo delataría.
- Maestra y nombres se normalizan a NFC. Guardado atómico (temporal + renombrar).
- `crypton` para las dos capas. Se descartó `saltine` porque exige la librería C de libsodium, incómoda en Windows.
- CLI (`app/Main.hs`): `color`, `init`, `add`, `gen` (genera o reemplaza con confirmación), `get`, `edit`, `mv`, `rm` (con confirmación), `list`, `passwd` (sal, verificación y Argon2 nuevos; vuelve a sellar todo). Generador en `src/Sulfur/Password.hs`: 76 caracteres sin sesgo de módulo, al menos uno de cada clase, 24 por default. Entrada con `haskeline` sin historial solo si stdin es consola real; si no (pipe, Git Bash) se lee como UTF-8 y sin `\r`, porque haskeline decodificaría con la página de códigos del sistema y una maestra con "ñ" daría otra clave. Bóveda en `%APPDATA%\sulfur\vault.json` o donde diga `SULFUR_VAULT`. En Windows cambia la consola a UTF-8 mientras corre y la restaura al salir.
- Pruebas con QuickCheck en `test/Spec.hs`: huella (gamut, rango, NFC, valor de referencia) y bóveda (ida y vuelta, maestra equivocada, nonces distintos, cualquier byte alterado, duplicados, JSON, parámetros abusivos).
- `docs/modelo-de-amenazas.md`: documento para la revisión externa. Mantenerlo al día cuando cambie el diseño criptográfico o el formato.
- Interfaz web después, si se decide.

## Decisiones pendientes

- `get` solo escribe a una terminal real. Alternativa: copiar al portapapeles (en Windows `clip.exe`, pero el historial del portapapeles puede retenerlo).
- En Git Bash (mintty) la salida no cuenta como terminal, así que `get` se niega; en PowerShell, cmd y la terminal de VS Code sí funciona.
- Reversión completa sin detectar: el índice atrapa entradas borradas, reordenadas o reinsertadas, pero restaurar el archivo entero a una versión vieja sigue siendo válido. Arreglarlo requiere un contador guardado fuera del archivo (si se pierde, la bóveda queda bloqueada).
- El tamaño de cada blob delata la longitud de nombre más secreto (sin relleno). Propuesta: rellenar a múltiplos fijos antes de sellar.
- Los `Text` con secretos no se borran de memoria al liberarse (limitación del GC de Haskell); solo la clave derivada vive en memoria que se borra.
- Formato de salida de la imagen: tamaño, cuadrícula, degradado o sólido por zona.
- Si la huella visual se muestra en la bóveda de Obsidian o solo en el CLI.
- Contra qué fondo se mide el contraste mínimo de la huella (depende de dónde se muestre).
