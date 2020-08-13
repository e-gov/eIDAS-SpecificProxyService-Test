package ee.ria.specificproxyservice

import io.qameta.allure.Allure
import io.qameta.allure.Step
import org.opensaml.saml.saml2.core.AuthnRequest

class Steps {
    static String LOA_HIGH = "http://eidas.europa.eu/LoA/high"

    public static String getAuthnRequestWithDefault(Flow flow) {
        return getAuthnRequest(flow, "DEMO-SP-CA", LOA_HIGH);
    }

    @Step("Create Natural Person authentication request")
    public static String getAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH) {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequest(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}:${flow.specificProxyService.port}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa);
        String stringResponse = OpenSAMLUtils.getXmlString(request);
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml");

        SamlSigantureUtils.validateSamlReqSignature(stringResponse);
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()));
    }
}
