package ee.ria.specificproxyservice

import io.restassured.path.xml.XmlPath

import static ee.ria.specificproxyservice.MetadataUtils.*
import static org.hamcrest.Matchers.not
import static org.hamcrest.Matchers.containsString
import static org.junit.Assert.assertEquals


class MetadataSpec extends SpecificProxyServiceSpecification {
    Flow flow = new Flow(props)

    def "Specific proxy service metadata has valid signature"() {
        expect:
        String metadata = Requests.getMetadataBody(flow.specificProxyService.fullMetadataUrl)
        validateMetadataSignature(metadata)
    }

    def "Connector metadata has valid signature and does not contain SPType"() {
        expect:
        String metadata = Requests.getMetadataBody(flow.connector.fullMetadataUrl)
        validateMetadataSignature(metadata)
        metadata(not(containsString("SPType")))

    }

    def "Specific proxy service metadata has node country defined"() {
        expect:
        String metadataXml = Requests.getMetadataBody(flow.specificProxyService.fullMetadataUrl)
        XmlPath xmlPath = new XmlPath(metadataXml)

        String nodeCountry = xmlPath.getString("EntityDescriptor.IDPSSODescriptor.Extensions.NodeCountry")
        assertEquals("EE", nodeCountry)
    }
}
