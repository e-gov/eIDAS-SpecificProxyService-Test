package ee.ria.specificproxyservice


class MetadataSpec extends SpecificProxyServiceSpecification {
    Flow flow = new Flow(props)

    def "Metadata has valid signature"() {
        expect:
        MetadataUtils.validateMetadataSignature(Requests.getMetadataBody(flow))
    }
}