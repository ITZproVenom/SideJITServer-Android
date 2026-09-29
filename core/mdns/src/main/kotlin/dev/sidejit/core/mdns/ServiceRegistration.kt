package dev.sidejit.core.mdns

import java.net.InetAddress

/**
 * One service we publish. The instance name is what a browser shows; the service type
 * is the usual `_name._tcp` pair. Addresses are supplied by the caller so the responder
 * never has to guess which interface a query arrived on.
 */
data class ServiceRegistration(
    val instanceName: String,
    val serviceType: String,
    val hostName: String,
    val port: Int,
    val txtRecords: Map<String, String> = emptyMap(),
    val domain: String = "local",
) {
    init {
        require(instanceName.isNotBlank()) { "the instance name may not be blank" }
        require(instanceName.toByteArray(Charsets.UTF_8).size <= 63) {
            "the instance name must fit in one DNS label"
        }
        require(serviceType.startsWith("_")) { "a service type starts with an underscore" }
        require(port in 1..65535) { "the port is out of range" }
    }

    /** `_remotepairing-pairable-host._tcp.local.` */
    val typeName: DnsName = DnsName(serviceType.trim('.').split('.') + domain)

    /** `SideJIT Server._remotepairing-pairable-host._tcp.local.` */
    val fullName: DnsName = DnsName(listOf(instanceName) + typeName.labels)

    /** `idevice-0123abcd.local.` */
    val hostDnsName: DnsName = DnsName(hostName.trim('.').split('.').let {
        if (it.size == 1) it + domain else it
    })

    companion object {
        /** The meta query a browser uses to list every service type on the link. */
        val SERVICE_ENUMERATION: DnsName = DnsName("_services._dns-sd._udp.local")
    }
}

/**
 * The authoritative record set for the services we publish. Pure: it turns questions
 * into answers and holds no sockets, so it can be tested without a network.
 */
class ServiceRecords(
    private val services: List<ServiceRegistration>,
    private val addressesFor: (ServiceRegistration) -> List<InetAddress>,
) {
    /** Every record we would announce unprompted. */
    fun announcement(): List<DnsRecord> = services.flatMap { service ->
        buildList {
            add(DnsRecord.Pointer(ServiceRegistration.SERVICE_ENUMERATION, service.typeName))
            add(DnsRecord.Pointer(service.typeName, service.fullName))
            add(DnsRecord.Service(service.fullName, service.hostDnsName, service.port))
            add(DnsRecord.Text(service.fullName, service.txtRecords))
            addAll(addressRecords(service))
        }
    }

    /** The same records with a zero lifetime, which retires them from every cache. */
    fun goodbye(): List<DnsRecord> = announcement().map { record ->
        when (record) {
            is DnsRecord.Pointer -> record.copy(ttlSeconds = 0)
            is DnsRecord.Service -> record.copy(ttlSeconds = 0)
            is DnsRecord.Text -> record.copy(ttlSeconds = 0)
            is DnsRecord.Address -> record.copy(ttlSeconds = 0)
            is DnsRecord.Opaque -> record.copy(ttlSeconds = 0)
        }
    }

    private fun addressRecords(service: ServiceRegistration): List<DnsRecord> =
        addressesFor(service).map { DnsRecord.Address(service.hostDnsName, it) }

    /**
     * Answers for one question, plus the extra records a resolver would ask for next.
     * Returns an empty answer list when the question is not ours, which is the common case.
     */
    fun respondTo(question: DnsQuestion): Pair<List<DnsRecord>, List<DnsRecord>> {
        val answers = ArrayList<DnsRecord>()
        val additional = ArrayList<DnsRecord>()
        for (service in services) {
            val srv = DnsRecord.Service(service.fullName, service.hostDnsName, service.port)
            val txt = DnsRecord.Text(service.fullName, service.txtRecords)
            val addresses = addressRecords(service)
            val wants = { type: Int -> question.type == type || question.type == DnsType.ANY }

            if (question.name == ServiceRegistration.SERVICE_ENUMERATION && wants(DnsType.PTR)) {
                answers.add(DnsRecord.Pointer(ServiceRegistration.SERVICE_ENUMERATION, service.typeName))
                continue
            }
            if (question.name == service.typeName && wants(DnsType.PTR)) {
                answers.add(DnsRecord.Pointer(service.typeName, service.fullName))
                additional.add(srv)
                additional.add(txt)
                additional.addAll(addresses)
                continue
            }
            if (question.name == service.fullName) {
                if (wants(DnsType.SRV)) {
                    answers.add(srv)
                    additional.addAll(addresses)
                }
                if (wants(DnsType.TXT)) answers.add(txt)
                continue
            }
            if (question.name == service.hostDnsName) {
                for (record in addresses) {
                    if (question.type == DnsType.ANY || question.type == record.type) answers.add(record)
                }
            }
        }
        val answerKeys = answers.map { it.name to it.type }.toSet()
        return answers.distinct() to additional.distinct().filter { (it.name to it.type) !in answerKeys }
    }

    /**
     * Section 7.1 of RFC 6762: a responder may stay quiet when the querier already
     * listed the answer with at least half its remaining lifetime.
     */
    fun isSuppressedBy(answer: DnsRecord, known: List<DnsRecord>): Boolean = known.any { entry ->
        entry.name == answer.name && entry.type == answer.type &&
            entry.ttlSeconds * 2 >= answer.ttlSeconds && sameData(entry, answer)
    }

    private fun sameData(left: DnsRecord, right: DnsRecord): Boolean {
        val leftData = DnsWriter().also { left.writeData(it) }.toByteArray()
        val rightData = DnsWriter().also { right.writeData(it) }.toByteArray()
        return leftData.contentEquals(rightData)
    }
}