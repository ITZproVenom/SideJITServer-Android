package dev.sidejit.core.serialization

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonTest {
    @Test
    fun `an object round trips and keeps its order`() {
        val value = jsonObject(
            "message" to jsonObject("plain" to jsonObject("_0" to JsonValue.of("hello"))),
            "originatedBy" to JsonValue.of("device"),
            "sequenceNumber" to JsonValue.of(3),
        )
        val encoded = value.encode()
        assertEquals(
            """{"message":{"plain":{"_0":"hello"}},"originatedBy":"device","sequenceNumber":3}""",
            encoded,
        )
        assertEquals("hello", JsonValue.parse(encoded).path("message", "plain", "_0")?.asText)
        assertEquals(3L, JsonValue.parse(encoded).path("sequenceNumber")?.asLong)
    }

    @Test
    fun `every scalar kind parses`() {
        val parsed = JsonValue.parse("""{"a":true,"b":false,"c":null,"d":-12.5,"e":"x","f":[1,2]}""")
        assertEquals(true, parsed.path("a")?.asBool)
        assertEquals(false, parsed.path("b")?.asBool)
        assertEquals(JsonValue.Null, parsed.path("c"))
        assertEquals(-12L, parsed.path("d")?.asLong)
        assertEquals("x", parsed.path("e")?.asText)
        assertEquals(2, parsed.path("f")?.asArray?.size)
    }

    @Test
    fun `escapes survive a round trip`() {
        val text = "quote \" backslash \\ newline \n tab \t control \u0001"
        val encoded = JsonValue.of(text).encode()
        assertEquals(text, JsonValue.parse(encoded).asText)
    }

    @Test
    fun `a unicode escape is decoded`() {
        assertEquals("\u00e9", JsonValue.parse("\"\\u00e9\"").asText)
    }

    @Test
    fun `empty containers parse`() {
        assertEquals(emptyMap<String, JsonValue>(), JsonValue.parse("{}").asObject)
        assertEquals(emptyList<JsonValue>(), JsonValue.parse("[]").asArray)
    }

    @Test
    fun `a missing path step returns null rather than throwing`() {
        assertNull(JsonValue.parse("""{"a":1}""").path("b", "c"))
        assertNull(JsonValue.parse("""{"a":1}""").path("a", "b"))
    }

    @Test
    fun `whitespace between tokens is allowed`() {
        assertEquals(1L, JsonValue.parse("  { \"a\" : 1 }  ").path("a")?.asLong)
    }

    @Test
    fun `malformed input is refused`() {
        val cases = listOf(
            "", "{", "[", "{\"a\"}", "{\"a\":}", "{'a':1}", "tru", "\"unterminated",
            "{\"a\":1}}", "[1,]x", "{\"a\":1,}",
        )
        for (case in cases) {
            var threw = false
            try {
                JsonValue.parse(case)
            } catch (failure: JsonValue.Companion.ParseException) {
                threw = true
            }
            assertTrue("expected '$case' to be refused", threw)
        }
    }

    @Test
    fun `deeply nested input is refused rather than overflowing the stack`() {
        var threw = false
        try {
            JsonValue.parse("[".repeat(200) + "]".repeat(200))
        } catch (failure: JsonValue.Companion.ParseException) {
            threw = true
        }
        assertTrue(threw)
    }
}