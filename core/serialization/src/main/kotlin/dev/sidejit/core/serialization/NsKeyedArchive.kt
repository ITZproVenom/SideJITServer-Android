package dev.sidejit.core.serialization

import java.io.ByteArrayOutputStream

object NsKeyedArchive {
    private const val MAGIC = "bplist00"

    sealed interface Value {
        data object Null : Value
        data class Bool(val value: Boolean) : Value
        data class Integer(val value: Long) : Value
        data class Real(val value: Double) : Value
        data class Text(val value: String) : Value
        data class Data(val value: ByteArray) : Value {
            override fun equals(other: Any?) = other is Data && other.value.contentEquals(value)
            override fun hashCode() = value.contentHashCode()
        }
        data class Array(val items: List<Value>) : Value
        data class Dict(val entries: LinkedHashMap<String, Value>) : Value {
            constructor(pairs: Map<String, Value>) : this(LinkedHashMap(pairs))
        }
    }

    fun dict(vararg pairs: Pair<String, Value>) = Value.Dict(linkedMapOf(*pairs))
    fun text(s: String) = Value.Text(s)
    fun bool(b: Boolean) = Value.Bool(b)
    fun integer(n: Long) = Value.Integer(n)
    fun array(vararg items: Value) = Value.Array(items.toList())
    fun array(items: List<Value>) = Value.Array(items)

    fun encode(root: Value): ByteArray = writeBplist(root)

    fun methodInvocation(selector: String, namedArgs: Map<String, Value>): ByteArray {
        val argsArray = array(namedArgs.map { (name, value) ->
            dict("name" to text(name), "value" to value)
        })
        return encode(dict("selector" to text(selector), "arguments" to argsArray))
    }

    private data class Node(
        val kind: Int, val bool: Boolean = false, val intVal: Long = 0, val real: Double = 0.0,
        val text: String = "", val data: ByteArray = ByteArray(0),
        val children: IntArray = IntArray(0), val keyIndexes: IntArray = IntArray(0),
    )

    private fun writeBplist(root: Value): ByteArray {
        val nodes = mutableListOf<Node>()
        fun intern(v: Value): Int {
            val idx = nodes.size
            when (v) {
                is Value.Null -> { nodes += Node(0); return idx }
                is Value.Bool -> { nodes += Node(1, bool = v.value); return idx }
                is Value.Integer -> { nodes += Node(2, intVal = v.value); return idx }
                is Value.Real -> { nodes += Node(3, real = v.value); return idx }
                is Value.Text -> { nodes += Node(4, text = v.value); return idx }
                is Value.Data -> { nodes += Node(5, data = v.value); return idx }
                is Value.Array -> {
                    nodes += Node(6)
                    val refs = IntArray(v.items.size)
                    for (i in v.items.indices) refs[i] = intern(v.items[i])
                    nodes[idx] = Node(6, children = refs)
                    return idx
                }
                is Value.Dict -> {
                    nodes += Node(7)
                    val keys = v.entries.keys.toList()
                    val vals = v.entries.values.toList()
                    val keyRefs = IntArray(keys.size)
                    val valRefs = IntArray(vals.size)
                    for (i in keys.indices) {
                        keyRefs[i] = intern(Value.Text(keys[i]))
                        valRefs[i] = intern(vals[i])
                    }
                    nodes[idx] = Node(7, children = valRefs, keyIndexes = keyRefs)
                    return idx
                }
            }
        }
        val rootIdx = intern(root)
        val body = ByteArrayOutputStream()
        body.write(MAGIC.toByteArray(Charsets.US_ASCII))
        val offsets = LongArray(nodes.size)
        for (i in nodes.indices) {
            offsets[i] = body.size().toLong()
            val n = nodes[i]
            when (n.kind) {
                0 -> body.write(0x00)
                1 -> body.write(if (n.bool) 0x09 else 0x08)
                2 -> writeIntObject(body, n.intVal)
                3 -> {
                    body.write(0x23)
                    val bits = java.lang.Double.doubleToRawLongBits(n.real)
                    for (s in 56 downTo 0 step 8) body.write(((bits ushr s) and 0xFF).toInt())
                }
                4 -> {
                    val utf16 = n.text.toByteArray(Charsets.UTF_16BE)
                    writeSizedMarker(body, 0x60, n.text.length)
                    body.write(utf16)
                }
                5 -> {
                    writeSizedMarker(body, 0x40, n.data.size)
                    body.write(n.data)
                }
                6 -> {
                    writeSizedMarker(body, 0xA0, n.children.size)
                    for (r in n.children) writeUid(body, r)
                }
                7 -> {
                    writeSizedMarker(body, 0xD0, n.keyIndexes.size)
                    for (r in n.keyIndexes) writeUid(body, r)
                    for (r in n.children) writeUid(body, r)
                }
            }
        }
        val offsetTableStart = body.size().toLong()
        val maxOffset = offsets.maxOrNull() ?: 0L
        val offsetSize = when { maxOffset < 0x100 -> 1; maxOffset < 0x10000 -> 2; else -> 4 }
        val refSize = when { nodes.size < 0x100 -> 1; nodes.size < 0x10000 -> 2; else -> 4 }
        for (off in offsets) writeFixed(body, off, offsetSize)
        repeat(6) { body.write(0) }
        body.write(offsetSize); body.write(refSize)
        writeFixed(body, nodes.size.toLong(), 8)
        writeFixed(body, rootIdx.toLong(), 8)
        writeFixed(body, offsetTableStart, 8)
        return body.toByteArray()
    }

    private fun writeSizedMarker(out: ByteArrayOutputStream, base: Int, count: Int) {
        if (count < 15) out.write(base or count)
        else { out.write(base or 0x0F); writeIntObject(out, count.toLong()) }
    }

    private fun writeIntObject(out: ByteArrayOutputStream, value: Long) {
        when {
            value in 0..0xFF -> { out.write(0x10); out.write(value.toInt()) }
            value in 0..0xFFFF -> {
                out.write(0x11)
                out.write(((value ushr 8) and 0xFF).toInt()); out.write((value and 0xFF).toInt())
            }
            value in 0..0xFFFFFFFFL -> {
                out.write(0x12)
                for (s in 24 downTo 0 step 8) out.write(((value ushr s) and 0xFF).toInt())
            }
            else -> {
                out.write(0x13)
                for (s in 56 downTo 0 step 8) out.write(((value ushr s) and 0xFF).toInt())
            }
        }
    }

    private fun writeUid(out: ByteArrayOutputStream, index: Int) {
        when {
            index < 0x100 -> { out.write(0x80); out.write(index) }
            index < 0x10000 -> {
                out.write(0x81)
                out.write((index ushr 8) and 0xFF); out.write(index and 0xFF)
            }
            else -> {
                out.write(0x83)
                for (s in 24 downTo 0 step 8) out.write((index ushr s) and 0xFF)
            }
        }
    }

    private fun writeFixed(out: ByteArrayOutputStream, value: Long, size: Int) {
        for (s in ((size - 1) * 8) downTo 0 step 8) out.write(((value ushr s) and 0xFF).toInt())
    }
}
