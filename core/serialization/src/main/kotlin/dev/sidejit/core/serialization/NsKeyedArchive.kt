package dev.sidejit.core.serialization

import java.io.ByteArrayOutputStream

/** NSKeyedArchiver-compatible binary plist encoder/decoder for DTX payloads. */
object NsKeyedArchive {
    private const val MAGIC = "bplist00"
    private const val ARCHIVER_NAME = "NSKeyedArchiver"
    private const val ARCHIVER_VERSION = 100000L
    private const val MAX_OBJECTS = 1_000_000

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

    fun dict(vararg pairs: Pair<String, Value>): Value.Dict = Value.Dict(linkedMapOf(*pairs))
    fun text(s: String): Value.Text = Value.Text(s)
    fun bool(b: Boolean): Value.Bool = Value.Bool(b)
    fun integer(n: Long): Value.Integer = Value.Integer(n)
    fun array(vararg items: Value): Value.Array = Value.Array(items.toList())
    fun array(items: List<Value>): Value.Array = Value.Array(items)

    fun encode(root: Value): ByteArray {
        val archive = ArchiveBuilder()
        val rootIndex = archive.archive(root)
        val document = PValue.Dict(linkedMapOf(
            "$" + "archiver" to PValue.Text(ARCHIVER_NAME),
            "$" + "version" to PValue.Integer(ARCHIVER_VERSION),
            "$" + "top" to PValue.Dict(linkedMapOf("root" to PValue.Uid(rootIndex.toLong()))),
            "$" + "objects" to PValue.Array(archive.objects.toList()),
        ))
        return writePlist(document)
    }

    fun methodInvocation(selector: String, namedArgs: Map<String, Value>): ByteArray {
        val arguments = array(namedArgs.map { (name, value) ->
            dict("name" to text(name), "value" to value)
        })
        return encode(dict("selector" to text(selector), "arguments" to arguments))
    }

    /** Decode a keyed-archive response whose root object is an integer PID. */
    fun readRootInteger(bytes: ByteArray): Long {
        val document = BplistParser(bytes).parseRoot() as? Parsed.Dict
            ?: throw IllegalArgumentException("binary plist root is not a dictionary")
        val top = document.values["$" + "top"] as? Parsed.Dict
            ?: throw IllegalArgumentException("binary plist is missing " + "$" + "top")
        val rootUid = top.values["root"] as? Parsed.Uid
            ?: throw IllegalArgumentException("binary plist " + "$" + "top" + " is missing root UID")
        val objects = document.values["$" + "objects"] as? Parsed.ArrayValue
            ?: throw IllegalArgumentException("binary plist is missing " + "$" + "objects")
        val root = objects.items.getOrNull(rootUid.index)
            ?: throw IllegalArgumentException("root UID " + rootUid.index + " is outside " + "$" + "objects")
        return when (root) {
            is Parsed.Integer -> root.value
            is Parsed.Uid -> {
                val target = objects.items.getOrNull(root.index)
                    ?: throw IllegalArgumentException("PID UID " + root.index + " is outside " + "$" + "objects")
                (target as? Parsed.Integer)?.value
                    ?: throw IllegalArgumentException("keyed archive root UID does not point to an integer")
            }
            else -> throw IllegalArgumentException("keyed archive root is not an integer")
        }
    }

    private sealed interface PValue {
        data object Null : PValue
        data class Bool(val value: Boolean) : PValue
        data class Integer(val value: Long) : PValue
        data class Real(val value: Double) : PValue
        data class Text(val value: String) : PValue
        data class Data(val value: ByteArray) : PValue
        data class Array(val items: List<PValue>) : PValue
        data class Dict(val entries: LinkedHashMap<String, PValue>) : PValue
        data class Uid(val value: Long) : PValue
    }

    private class ArchiveBuilder {
        val objects = ArrayList<PValue>().apply { add(PValue.Text("$" + "null")) }

        fun archive(value: Value): Int = when (value) {
            Value.Null -> add(PValue.Text("$" + "null"))
            is Value.Bool -> add(PValue.Bool(value.value))
            is Value.Integer -> add(PValue.Integer(value.value))
            is Value.Real -> add(PValue.Real(value.value))
            is Value.Text -> add(PValue.Text(value.value))
            is Value.Data -> add(PValue.Data(value.value))
            is Value.Array -> {
                require(value.items.size <= Int.MAX_VALUE) { "array is too large" }
                val index = objects.size
                objects.add(PValue.Null)
                val itemRefs = value.items.map { PValue.Uid(archive(it).toLong()) }
                val classIndex = addClass("NSArray", listOf("NSArray", "NSObject"))
                objects[index] = PValue.Dict(linkedMapOf(
                    "$" + "class" to PValue.Uid(classIndex.toLong()),
                    "NS.objects" to PValue.Array(itemRefs),
                ))
                index
            }
            is Value.Dict -> {
                val index = objects.size
                objects.add(PValue.Null)
                val keys = ArrayList<PValue>(value.entries.size)
                val values = ArrayList<PValue>(value.entries.size)
                for ((key, item) in value.entries) {
                    keys += PValue.Uid(archive(Value.Text(key)).toLong())
                    values += PValue.Uid(archive(item).toLong())
                }
                val classIndex = addClass("NSDictionary", listOf("NSDictionary", "NSObject"))
                objects[index] = PValue.Dict(linkedMapOf(
                    "$" + "class" to PValue.Uid(classIndex.toLong()),
                    "NS.keys" to PValue.Array(keys),
                    "NS.objects" to PValue.Array(values),
                ))
                index
            }
        }

        private fun add(value: PValue): Int {
            require(objects.size < MAX_OBJECTS) { "NSKeyedArchive object table is too large" }
            val index = objects.size
            objects.add(value)
            return index
        }

        private fun addClass(name: String, classes: List<String>): Int = add(PValue.Dict(linkedMapOf(
            "$" + "classname" to PValue.Text(name),
            "$" + "classes" to PValue.Array(classes.map(PValue::Text)),
        )))
    }

    private data class Node(
        val kind: Kind,
        val bool: Boolean = false,
        val integer: Long = 0L,
        val real: Double = 0.0,
        val bytes: ByteArray = ByteArray(0),
        val text: String = "",
        val refs: IntArray = IntArray(0),
        val uid: Long = 0L,
    )

    private enum class Kind { NULL, BOOL, INTEGER, REAL, DATA, STRING, UTF16, ARRAY, DICT, UID }

    private fun writePlist(root: PValue): ByteArray {
        val nodes = ArrayList<Node>()
        fun intern(value: PValue): Int {
            val index = nodes.size
            when (value) {
                PValue.Null -> nodes += Node(Kind.NULL)
                is PValue.Bool -> nodes += Node(Kind.BOOL, bool = value.value)
                is PValue.Integer -> nodes += Node(Kind.INTEGER, integer = value.value)
                is PValue.Real -> nodes += Node(Kind.REAL, real = value.value)
                is PValue.Text -> {
                    if (value.value.all { it.code <= 0x7F }) nodes += Node(Kind.STRING, text = value.value)
                    else nodes += Node(Kind.UTF16, text = value.value)
                }
                is PValue.Data -> nodes += Node(Kind.DATA, bytes = value.value)
                is PValue.Array -> nodes += Node(Kind.ARRAY, refs = value.items.map { intern(it) }.toIntArray())
                is PValue.Dict -> {
                    val pairs = value.entries.map { (key, item) -> intern(PValue.Text(key)) to intern(item) }
                    val refs = IntArray(pairs.size * 2)
                    for (i in pairs.indices) {
                        refs[i] = pairs[i].first
                        refs[pairs.size + i] = pairs[i].second
                    }
                    nodes += Node(Kind.DICT, refs = refs)
                }
                is PValue.Uid -> nodes += Node(Kind.UID, uid = value.value)
            }
            return index
        }

        val rootIndex = intern(root)
        require(nodes.size in 1..MAX_OBJECTS) { "invalid NSKeyedArchive object count" }
        val refSize = when {
            nodes.size <= 0xFF -> 1
            nodes.size <= 0xFFFF -> 2
            nodes.size.toLong() <= 0xFFFF_FFFFL -> 4
            else -> 8
        }
        val offsets = LongArray(nodes.size)
        var cursor = 8L
        for (i in nodes.indices) {
            offsets[i] = cursor
            cursor += nodeSize(nodes[i], refSize).toLong()
        }
        val offsetTableStart = cursor
        val maxOffset = offsets.maxOrNull() ?: 8L
        val offsetSize = when {
            maxOffset < 0x100 -> 1
            maxOffset < 0x1_0000 -> 2
            maxOffset < 0x1_0000_0000L -> 4
            else -> 8
        }

        val out = ByteArrayOutputStream()
        out.write(MAGIC.toByteArray(Charsets.US_ASCII))
        for (node in nodes) writeNode(out, node, offsets, refSize)
        for (offset in offsets) writeFixed(out, offset, offsetSize)
        repeat(6) { out.write(0) }
        out.write(offsetSize)
        out.write(refSize)
        writeFixed(out, nodes.size.toLong(), 8)
        writeFixed(out, rootIndex.toLong(), 8)
        writeFixed(out, offsetTableStart, 8)
        return out.toByteArray()
    }

    private fun nodeSize(node: Node, refSize: Int): Int = when (node.kind) {
        Kind.NULL, Kind.BOOL -> 1
        Kind.INTEGER -> integerObjectWidth(node.integer)
        Kind.REAL -> 9
        Kind.DATA -> sizedMarkerSize(node.bytes.size) + node.bytes.size
        Kind.STRING -> sizedMarkerSize(node.text.toByteArray(Charsets.US_ASCII).size) + node.text.toByteArray(Charsets.US_ASCII).size
        Kind.UTF16 -> sizedMarkerSize(node.text.length) + node.text.length * 2
        Kind.ARRAY -> sizedMarkerSize(node.refs.size) + node.refs.size * refSize
        Kind.DICT -> sizedMarkerSize(node.refs.size / 2) + node.refs.size * refSize
        Kind.UID -> 1 + uidWidth(node.uid)
    }

    private fun writeNode(out: ByteArrayOutputStream, node: Node, offsets: LongArray, refSize: Int) {
        when (node.kind) {
            Kind.NULL -> out.write(0x00)
            Kind.BOOL -> out.write(if (node.bool) 0x09 else 0x08)
            Kind.INTEGER -> writeIntObject(out, node.integer)
            Kind.REAL -> { out.write(0x23); writeFixed(out, java.lang.Double.doubleToRawLongBits(node.real), 8) }
            Kind.DATA -> { writeSizedMarker(out, 0x40, node.bytes.size); out.write(node.bytes) }
            Kind.STRING -> { val raw = node.text.toByteArray(Charsets.US_ASCII); writeSizedMarker(out, 0x50, raw.size); out.write(raw) }
            Kind.UTF16 -> { val raw = node.text.toByteArray(Charsets.UTF_16BE); writeSizedMarker(out, 0x60, node.text.length); out.write(raw) }
            Kind.ARRAY -> { writeSizedMarker(out, 0xA0, node.refs.size); node.refs.forEach { writeFixed(out, it.toLong(), refSize) } }
            Kind.DICT -> {
                val count = node.refs.size / 2
                writeSizedMarker(out, 0xD0, count)
                for (i in 0 until count) writeFixed(out, node.refs[i].toLong(), refSize)
                for (i in 0 until count) writeFixed(out, node.refs[count + i].toLong(), refSize)
            }
            Kind.UID -> {
                val width = uidWidth(node.uid)
                out.write(0x80 or (width - 1))
                writeFixed(out, node.uid, width)
            }
        }
    }

    private fun sizedMarkerSize(count: Int): Int = if (count < 15) 1 else 1 + integerObjectWidth(count.toLong())

    private fun writeSizedMarker(out: ByteArrayOutputStream, base: Int, count: Int) {
        if (count < 15) {
            out.write(base or count)
        } else {
            out.write(base or 0x0F)
            writeIntObject(out, count.toLong())
        }
    }

    private fun integerObjectWidth(value: Long): Int = when {
        value >= 0 && value <= 0xFF -> 2
        value >= 0 && value <= 0xFFFF -> 3
        value >= 0 && value <= 0xFFFF_FFFFL -> 5
        else -> 9
    }

    private fun writeIntObject(out: ByteArrayOutputStream, value: Long) {
        when {
            value >= 0 && value <= 0xFF -> { out.write(0x10); writeFixed(out, value, 1) }
            value >= 0 && value <= 0xFFFF -> { out.write(0x11); writeFixed(out, value, 2) }
            value >= 0 && value <= 0xFFFF_FFFFL -> { out.write(0x12); writeFixed(out, value, 4) }
            else -> { out.write(0x13); writeFixed(out, value, 8) }
        }
    }

    private fun uidWidth(value: Long): Int = when {
        value <= 0xFF -> 1
        value <= 0xFFFF -> 2
        value <= 0xFFFF_FFFF -> 4
        else -> 8
    }

    private fun writeFixed(out: ByteArrayOutputStream, value: Long, width: Int) {
        for (shift in (width - 1) * 8 downTo 0 step 8) out.write(((value ushr shift) and 0xFF).toInt())
    }

    private sealed interface Parsed {
        data object Null : Parsed
        data class Bool(val value: Boolean) : Parsed
        data class Integer(val value: Long) : Parsed
        data class Real(val value: Double) : Parsed
        data class DataValue(val value: ByteArray) : Parsed
        data class Text(val value: String) : Parsed
        data class Uid(val index: Int) : Parsed
        data class ArrayValue(val items: List<Parsed>) : Parsed
        data class Dict(val values: Map<String, Parsed>) : Parsed
    }

    private class BplistParser(private val data: ByteArray) {
        private val offsetSize: Int
        private val refSize: Int
        private val objectCount: Int
        private val topObject: Int
        private val offsetTable: Long
        private val cache = HashMap<Int, Parsed>()

        init {
            require(data.size >= 40) { "binary plist is truncated" }
            require(String(data, 0, 8, Charsets.US_ASCII) == MAGIC) { "not a binary plist" }
            val trailer = data.size - 32
            offsetSize = u8(trailer + 6)
            refSize = u8(trailer + 7)
            val count = u64(trailer + 8)
            val top = u64(trailer + 16)
            offsetTable = u64(trailer + 24)
            require(offsetSize in 1..8 && refSize in 1..8) { "invalid binary plist sizes" }
            require(count in 1..MAX_OBJECTS.toLong()) { "invalid binary plist object count" }
            require(top < count) { "invalid binary plist top object" }
            require(offsetTable >= 8 && offsetTable < trailer) { "invalid binary plist offset table" }
            objectCount = count.toInt()
            topObject = top.toInt()
        }

        fun parseRoot(): Parsed = readObject(topObject)

        private fun readObject(index: Int): Parsed {
            require(index in 0 until objectCount) { "binary plist object index $index is out of range" }
            cache[index]?.let { return it }
            val refOffset = Math.multiplyExact(index, refSize)
            val offsetPos = Math.addExact(offsetTable.toInt(), refOffset)
            require(offsetPos + offsetSize <= data.size - 32) { "binary plist object offset is truncated" }
            val offset = readUnsigned(offsetPos, offsetSize).toInt()
            require(offset in 8 until data.size - 32) { "binary plist object offset is out of range" }
            val marker = u8(offset)
            val type = marker ushr 4
            val value = when (type) {
                0x0 -> when (marker) { 0x00 -> Parsed.Null; 0x08 -> Parsed.Bool(false); 0x09 -> Parsed.Bool(true); else -> throw IllegalArgumentException("unsupported binary plist marker 0x" + marker.toString(16)) }
                0x1 -> Parsed.Integer(readInteger(offset, marker))
                0x2 -> { val width = 1 shl (marker and 0x0F); require(width == 8) { "unsupported binary plist real width $width" }; Parsed.Real(Double.fromBits(readUnsigned(offset + 1, width))) }
                0x4 -> { val (length, start) = sizedObject(offset, marker); Parsed.DataValue(readBytes(start, length)) }
                0x5 -> { val (length, start) = sizedObject(offset, marker); Parsed.Text(String(readBytes(start, length), Charsets.US_ASCII)) }
                0x6 -> { val (length, start) = sizedObject(offset, marker); Parsed.Text(String(readBytes(start, length * 2), Charsets.UTF_16BE)) }
                0x8 -> { val width = (marker and 0x0F) + 1; Parsed.Uid(readUnsigned(offset + 1, width).toInt()) }
                0xA -> {
                    val (length, start) = sizedObject(offset, marker)
                    require(length <= MAX_OBJECTS) { "binary plist array is too large" }
                    Parsed.ArrayValue(List(length) { readObject(readUnsigned(start + it * refSize, refSize).toInt()) })
                }
                0xD -> {
                    val (length, start) = sizedObject(offset, marker)
                    require(length <= MAX_OBJECTS) { "binary plist dictionary is too large" }
                    val valuesStart = start + length * refSize
                    val values = LinkedHashMap<String, Parsed>(length)
                    for (i in 0 until length) {
                        val key = readObject(readUnsigned(start + i * refSize, refSize).toInt())
                        val value = readObject(readUnsigned(valuesStart + i * refSize, refSize).toInt())
                        val keyText = (key as? Parsed.Text)?.value
                            ?: throw IllegalArgumentException("binary plist dictionary key is not a string")
                        values[keyText] = value
                    }
                    Parsed.Dict(values)
                }
                else -> throw IllegalArgumentException("unsupported binary plist marker 0x" + marker.toString(16))
            }
            cache[index] = value
            return value
        }

        private fun readInteger(offset: Int, marker: Int): Long {
            val width = 1 shl (marker and 0x0F)
            require(width in 1..8) { "unsupported binary plist integer width $width" }
            return if (width == 8) readUnsigned(offset + 1, width) else readUnsigned(offset + 1, width)
        }

        private fun sizedObject(offset: Int, marker: Int): Pair<Int, Int> {
            val nibble = marker and 0x0F
            if (nibble < 15) return nibble to offset + 1
            val intMarker = u8(offset + 1)
            require(intMarker ushr 4 == 0x1) { "invalid extended binary plist length marker" }
            val width = 1 shl (intMarker and 0x0F)
            require(width in 1..8) { "invalid extended binary plist length width $width" }
            val length = readUnsigned(offset + 2, width).toInt()
            return length to offset + 2 + width
        }

        private fun readBytes(offset: Int, length: Int): ByteArray {
            require(length >= 0 && offset >= 0 && offset + length <= data.size - 32) { "binary plist object is truncated" }
            return data.copyOfRange(offset, offset + length)
        }

        private fun u8(offset: Int): Int = data[offset].toInt() and 0xFF
        private fun u64(offset: Int): Long = readUnsigned(offset, 8)
        private fun readUnsigned(offset: Int, width: Int): Long {
            require(width in 1..8 && offset >= 0 && offset + width <= data.size) { "invalid binary plist integer range" }
            var value = 0L
            for (i in 0 until width) value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
            return value
        }

        private fun Int.checkedAdd(delta: Int): Int = checkedAddLong(delta.toLong()).toInt()
        private fun checkedAddLong(delta: Long): Long = toLong().checkedAddLongInternal(delta)
        private fun Long.checkedAddLongInternal(delta: Long): Long {
            val result = this + delta
            require((delta >= 0 && result >= this) || (delta < 0 && result <= this)) { "binary plist offset overflow" }
            return result
        }
    }
}
