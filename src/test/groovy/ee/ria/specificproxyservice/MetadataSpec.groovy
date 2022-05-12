package ee.ria.specificproxyservice

import org.hamcrest.Matchers


class MetadataSpec extends SpecificProxyServiceSpecification {
    Flow flow = new Flow(props)

    def "Specific proxy service metadata has valid signature"() {
        expect:
        String metadata = Requests.getMetadataBody(flow.specificProxyService.fullMetadataUrl)
        MetadataUtils.validateMetadataSignature(metadata)
    }

    def "Connector metadata has valid signature and does not contain SPType"() {
        expect:
        String metadata = Requests.getMetadataBody(flow.connector.fullMetadataUrl)
        MetadataUtils.validateMetadataSignature(metadata)
        metadata(Matchers.not(Matchers.containsString("SPType")))

    }
}