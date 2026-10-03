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

- Build con cabal (`sulfur.cabal`), toolchain vía GHCup en `C:\ghcup`.
- Núcleo puro en `src/Sulfur/`: texto normalizado a NFC (`unicode-transforms`), en UTF-8, a SHA-256, a color OKLCH con croma recortado a sRGB (`Fingerprint.hs`). Imagen después (PNG vía JuicyPixels).
- Bóveda: archivo JSON (`aeson`) con cada entrada cifrada por separado, nonce aleatorio propio por entrada y el nombre de la entrada como dato asociado (AAD), para que mover un cifrado a otro nombre haga fallar el descifrado. La huella nunca se guarda en disco: se calcula al vuelo, porque es un hash sin sal del nombre y lo delataría.
- `crypton` para las dos capas: SHA-256 de la huella y, en la bóveda, Argon2id + ChaCha20-Poly1305. Se descartó `saltine` porque exige la librería C de libsodium, incómoda en Windows.
- Pruebas con QuickCheck en `test/Spec.hs`: dentro de sRGB, rango de luminosidad, nunca `#000`/`#fff`, más un valor fijo de referencia para detectar si el algoritmo cambia.
- CLI primero (`sulfur "<nombre>"`). Interfaz web después, si se decide.

## Decisiones pendientes

- Formato de salida de la imagen: tamaño, cuadrícula, degradado o sólido por zona.
- Nombres de entrada cifrados (recomendado: no filtra en qué servicios hay cuenta) o en claro (`list` sin pedir la maestra).
- Si la huella visual se muestra en la bóveda de Obsidian o solo en el CLI.
- Contra qué fondo se mide el contraste mínimo de la huella (depende de dónde se muestre).
- Cambiar el algoritmo de la huella cambia todos los colores ya memorizados: congelarlo antes de usarlo en serio.
