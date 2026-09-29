package dev.sidejit.core.serialization

/**
 * A small JSON reader and writer.
 *
 * The remote pairing control channel carries JSON envelopes, so this only needs to be
 * good enough for those: correct, strict about malformed input, and free of any
 * dependency that would have to be shipped in the application.
 */
sealed interface JsonValue {
    data object Null : JsonValue
    data class Bool(val value: Boolean) : JsonValue
    data class Num(val value: Double, val text: String) : JsonValue
    data class Text(val value: String) : JsonValue
    data class Arr(val items: List<JsonValue>) : JsonValue
    data class Obj(val entries: Map<String, JsonValue>) : JsonValue

    val asObject: Map<String, JsonValue>? get() = (this as? Obj)?.entries
    val asArray: List<JsonValue>? get() = (this as? Arr)?.items
    val asText: String? get() = (this as? Text)?.value
    val asBool: Boolean? get() = (this as? Bool)?.value
    val asLong: Long? get() = (this as? Num)?.value?.toLong()

    /** Walks nested objects, returning null as soon as a step is missing. */
    fun path(vararg keys: String): JsonValue? {
        var current: JsonValue? = this
        for (key in keys) current = (current as? Obj)?.entries?.get(key) ?: return null
        return current
    }

    fun encode(): String = StringBuilder().also { write(it) }.toString()

    private fun write(out: StringBuilder) {
        when (this) {
            is Null -> out.append("null")
            is Bool -> out.append(if (value) "true" else "false")
            is Num -> out.append(text)
            is Text -> writeString(out, value)
            is Arr -> {
                out.append('[')
                items.forEachIndexed { index, item ->
                    if (index > 0) out.append(',')
                    item.write(out)
                }
                out.append(']')
            }
            is Obj -> {
                out.append('{')
                var first = true
                for ((key, item) in entries) {
                    if (!first) out.append(',')
                    first = false
                    writeString(out, key)
                    out.append(':')
                    item.write(out)
                }
                out.append('}')
            }
        }
    }

    private fun writeString(out: StringBuilder, value: String) {
        out.append('"')
        for (character in value) {
            when {
                character == '"' -> out.append("\\\"")
                character == '\\' -> out.append("\\\\")
                character == '\n' -> out.append("\\n")
                character == '\r' -> out.append("\\r")
                character == '\t' -> out.append("\\t")
                character < ' ' -> out.append("\\u%04x".format(character.code))
                else -> out.append(character)
            }
        }
        out.append('"')
    }

    companion object {
        class ParseException(message: String) : Exception(message)

        fun of(value: String): JsonValue = Text(value)
        fun of(value: Boolean): JsonValue = Bool(value)
        fun of(value: Long): JsonValue = Num(value.toDouble(), value.toString())
        fun of(value: Int): JsonValue = of(value.toLong())

        fun parse(text: String): JsonValue {
            val parser = JsonParser(text)
            val value = parser.parseValue(0)
            parser.skipWhitespace()
            if (!parser.atEnd) throw ParseException("trailing characters after the JSON value")
            return value
        }
    }
}

/** Builds an object, keeping insertion order so encodings are reproducible. */
fun jsonObject(vararg entries: Pair<String, JsonValue>): JsonValue.Obj =
    JsonValue.Obj(linkedMapOf(*entries))

fun jsonArray(vararg items: JsonValue): JsonValue.Arr = JsonValue.Arr(items.toList())

private class JsonParser(private val text: String) {
    private var position = 0

    val atEnd: Boolean get() = position >= text.length

    fun skipWhitespace() {
        while (position < text.length && text[position].isWhitespace()) position++
    }

    fun parseValue(depth: Int): JsonValue {
        if (depth > 64) throw JsonValue.Companion.ParseException("the JSON value nests too deeply")
        skipWhitespace()
        if (atEnd) throw JsonValue.Companion.ParseException("the JSON value ended early")
        return when (val character = text[position]) {
            '{' -> parseObject(depth)
            '[' -> parseArray(depth)
            '"' -> JsonValue.Text(parseString())
            't' -> literal("true", JsonValue.Bool(true))
            'f' -> literal("false", JsonValue.Bool(false))
            'n' -> literal("null", JsonValue.Null)
            else -> if (character == '-' || character.isDigit()) {
                parseNumber()
            } else {
                throw JsonValue.Companion.ParseException("unexpected character '$character'")
            }
        }
    }

    private fun literal(expected: String, value: JsonValue): JsonValue {
        if (!text.startsWith(expected, position)) {
            throw JsonValue.Companion.ParseException("expected $expected")
        }
        position += expected.length
        return value
    }

    private fun expect(character: Char) {
        skipWhitespace()
        if (atEnd || text[position] != character) {
            throw JsonValue.Companion.ParseException("expected '$character'")
        }
        position++
    }

    private fun parseObject(depth: Int): JsonValue {
        expect('{')
        val entries = LinkedHashMap<String, JsonValue>()
        skipWhitespace()
        if (!atEnd && text[position] == '}') {
            position++
            return JsonValue.Obj(entries)
        }
        while (true) {
            skipWhitespace()
            val key = parseString()
            expect(':')
            entries[key] = parseValue(depth + 1)
            skipWhitespace()
            if (atEnd) throw JsonValue.Companion.ParseException("an object was not closed")
            when (text[position]) {
                ',' -> position++
                '}' -> {
                    position++
                    return JsonValue.Obj(entries)
                }
                else -> throw JsonValue.Companion.ParseException("expected ',' or '}'")
            }
        }
    }

    private fun parseArray(depth: Int): JsonValue {
        expect('[')
        val items = ArrayList<JsonValue>()
        skipWhitespace()
        if (!atEnd && text[position] == ']') {
            position++
            return JsonValue.Arr(items)
        }
        while (true) {
            items.add(parseValue(depth + 1))
            skipWhitespace()
            if (atEnd) throw JsonValue.Companion.ParseException("an array was not closed")
            when (text[position]) {
                ',' -> position++
                ']' -> {
                    position++
                    return JsonValue.Arr(items)
                }
                else -> throw JsonValue.Companion.ParseException("expected ',' or ']'")
            }
        }
    }

    private fun parseString(): String {
        if (atEnd || text[position] != '"') throw JsonValue.Companion.ParseException("expected a string")
        position++
        val builder = StringBuilder()
        while (true) {
            if (atEnd) throw JsonValue.Companion.ParseException("a string was not closed")
            when (val character = text[position++]) {
                '"' -> return builder.toString()
                '\\' -> {
                    if (atEnd) throw JsonValue.Companion.ParseException("a string ended inside an escape")
                    when (val escape = text[position++]) {
                        '"' -> builder.append('"')
                        '\\' -> builder.append('\\')
                        '/' -> builder.append('/')
                        'b' -> builder.append('\b')
                        'f' -> builder.append('\u000C')
                        'n' -> builder.append('\n')
                        'r' -> builder.append('\r')
                        't' -> builder.append('\t')
                        'u' -> {
                            if (position + 4 > text.length) {
                                throw JsonValue.Companion.ParseException("a truncated unicode escape")
                            }
                            val code = text.substring(position, position + 4).toIntOrNull(16)
                                ?: throw JsonValue.Companion.ParseException("a malformed unicode escape")
                            builder.append(code.toChar())
                            position += 4
                        }
                        else -> throw JsonValue.Companion.ParseException("an unknown escape '\\$escape'")
                    }
                }
                else -> builder.append(character)
            }
        }
    }

    private fun parseNumber(): JsonValue {
        val start = position
        if (!atEnd && text[position] == '-') position++
        while (!atEnd && (text[position].isDigit() || text[position] in ".eE+-")) position++
        val slice = text.substring(start, position)
        val value = slice.toDoubleOrNull()
            ?: throw JsonValue.Companion.ParseException("a malformed number '$slice'")
        return JsonValue.Num(value, slice)
    }
}