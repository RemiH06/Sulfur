import java.math.BigDecimal
import java.math.MathContext

fun main() {
    val password = "contrasena123"

    if (password != null) {
        val asciiArray = password.toCharArray()
            .map { it.toInt() }
            .filter { it in 32..126 }
            .map { it + 64 }
            .toIntArray()

        val hexArray = asciiArray.map { it.toString(16) }

        val colorArray = hexArray.mapIndexed { index, hexValue ->
            val position = (index + 1) % 3
            when (position) {
                1 -> "${hexValue}YYZZ"
                2 -> "XX${hexValue}ZZ"
                else -> "XXYY${hexValue}"
            }
        }

        val modifiedColorArray = colorArray.mapIndexed { index, colorValue ->
            val phi = calculateFibonacci(index, hexArray.size)
            if (colorValue.contains("XX")) {
                colorValue.replace("XX", hexArray[phi])
            } else if (colorValue.contains("YY")) {
                colorValue.replace("YY", hexArray[phi])
            } else {
                colorValue.replace("ZZ", hexArray[phi])
            }
        }

        val finalArray = modifiedColorArray.mapIndexed { index, colorValue ->
            val euler = generateEuler(255)
            val somePlace = minOf(asciiArray[maxOf(0, index-1)], asciiArray[minOf(index, asciiArray.size - 1)])
            val decimalResult = euler.substring(somePlace, somePlace + 2).let {
                if (it.toInt() + euler[somePlace + 1].toString().toInt() < 24) {
                    it + euler[somePlace + 2].toString()
                } else {
                    it
                }
            }.toInt()
            val replacementValue = decimalResult.toString(16)
            if (colorValue.contains("ZZ")) {
                colorValue.replace("ZZ", replacementValue)
            } else if (colorValue.contains("YY")) {
                colorValue.replace("YY", replacementValue)
            } else {
                colorValue.replace("XX", replacementValue)
            }
        }

        println("Valores ASCII de la contraseña:\n" + asciiArray.joinToString(", "))
        println("Valores hexadecimales de la contraseña:\n" + hexArray.joinToString(", "))
        println("Valores de color:\n" + colorArray.joinToString(", "))
        println("Valores de color pero con phi:\n" + modifiedColorArray.joinToString(", "))
        println("Valores de color con reemplazo final:\n" + finalArray.joinToString(", "))
    } else {
        println("La entrada de contraseña es nula.")
    }
}

fun hexToDecimal(hex: String): Int {
    return hex.toInt(16)
}

fun generateEuler(decimal: Int): String {
    var euler = BigDecimal.ONE
    var factorial = BigDecimal.ONE
    var increment = 7
    var decrement = 13
    var currentDecimal = decimal

    while (true) {
        euler = BigDecimal.ONE
        factorial = BigDecimal.ONE

        for (i in 1..currentDecimal) {
            factorial *= BigDecimal(i)
            euler += BigDecimal.ONE.divide(factorial, MathContext.DECIMAL128)
        }

        if (euler.toInt() > 255) {
            currentDecimal -= decrement

            if (currentDecimal <= 0) {
                currentDecimal = 7
                increment += 7
                decrement += 13
            }
        } else {
            break
        }
    }

    return euler.toString()
}

fun calculateFibonacci(n: Int, arraySize: Int): Int {
    if (n == 0 || n == 1) {
        return 1
    }
    var a = 1
    var b = 1
    var result = 0
    repeat(n - 1) {
        result = (a + b) % arraySize
        a = b
        b = result
    }
    return result
}