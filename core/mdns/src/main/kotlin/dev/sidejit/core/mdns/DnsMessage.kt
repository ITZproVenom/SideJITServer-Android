package dev.sidejit.core.mdns

data class DnsMessage(
    val id: Int = 0,
    val response: Boolean = false,
    val authoritative: Boolean = true,
    val truncated: Boolean = false,
    val questions: List<DnsQuestion> = emptyList(),
    val answers: List<DnsRecord> = emptyList(),
    val authority: List<DnsRecord> = emptyList(),
    val additional: List<DnsRecord> = emptyList(),
) {
    fun encode(): ByteArray {
        val writer = DnsWriter()
        var flags = 0
        if (response) flags = flags or 0x8000
        if (authoritative) flags = flags or 0x0400
        if (truncated) flags = flags or 0x0200
        writer.u16(id).u16(flags)
        writer.u16(questions.size).u16(answers.size).u16(authority.size).u16(additional.size)
        for (question in questions) {
            writer.name(question.name)
            writer.u16(question.type)
            writer.u16(
                if (question.unicastResponse) {
                    question.dnsClass or DnsClass.UNICAST_RESPONSE
                } else {
                    question.dnsClass
                },
            )
        }
        for (record in answers + authority + additional) record.write(writer)
        return writer.toByteArray()
    }

    companion object {
        /** The largest datagram we will send; multicast DNS keeps below the usual MTU. */
        const val MAX_DATAGRAM: Int = 1400

        fun decode(data: ByteArray, length: Int = data.size): DnsMessage {
            val reader = DnsReader(if (length == data.size) data else data.copyOf(length))
            val id = reader.u16()
            val flags = reader.u16()
            val questionCount = reader.u16()
            val answerCount = reader.u16()
            val authorityCount = reader.u16()
            val additionalCount = reader.u16()
            val questions = ArrayList<DnsQuestion>(questionCount)
            repeat(questionCount) {
                val name = reader.name()
                val type = reader.u16()
                val classField = reader.u16()
                questions.add(
                    DnsQuestion(
                        name,
                        type,
                        classField and DnsClass.UNICAST_RESPONSE != 0,
                        classField and 0x7FFF,
                    ),
                )
            }
            fun records(count: Int): List<DnsRecord> = (0 until count).map { DnsRecord.read(reader) }
            return DnsMessage(
                id = id,
                response = flags and 0x8000 != 0,
                authoritative = flags and 0x0400 != 0,
                truncated = flags and 0x0200 != 0,
                questions = questions,
                answers = records(answerCount),
                authority = records(authorityCount),
                additional = records(additionalCount),
            )
        }
    }
}