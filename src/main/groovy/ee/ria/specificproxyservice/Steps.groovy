package ee.ria.specificproxyservice

import ee.ria.specificproxyservice.tara.MobileId
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.NameIDType

class Steps {
    static String LOA_HIGH = "http://eidas.europa.eu/LoA/high"

    @Step("Create Natural Person authentication request")
    static String getAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison,nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request with missing extensions")
    static String getAuthnRequestWithMissingNaturalExtensions(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestWithMissingNaturalExtensions(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison,nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create legal Person authentication request with missing extensions")
    static String getAuthnRequestWithMissingLegalExtensions(Flow flow, String providerName, String loa = LOA_HIGH) {
        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestWithMissingLegalExtensions(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create authentication request with natural and legal person extensions")
    static String getAuthnRequestWithNaturalAndLegalExtensions(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestWithNaturalAndLegalExtensions(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison,nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request without nameIdFormat attribute")
    static String getAuthnRequestWithoutNameIdFormat(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison, null, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request with optional attributes")
    static String getAuthnRequestWithOptionalAttributes(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestWithOptionalAttributes(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison,nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Legal Person authentication request with minimal attributes")
    static String getLegalPersonAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH) {

        AuthnRequest request = new RequestBuilderUtils().buildLegalAuthnRequest(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Legal Person authentication request with optional attributes")
    static String getOptionalLegalPersonAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH) {

        AuthnRequest request = new RequestBuilderUtils().buildOptionalLegalAuthnRequest(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Start authentication flow in eIDAS node")
    static Response startAuthProcessInEidasNode(Flow flow, String samlRequest) {
        Response response1 = Requests.colleagueRequest(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        return Requests.proxyServiceRequest(flow, action, token)
    }

    @Step("Finish authentication flow in eIDAS node")
    static Response finishAuthProcessInEidasNode(Flow flow, String url) {
        Response response1 = Requests.idpResponse(flow, url)
        return Requests.specificProxyResponse(flow, response1.getHeader("Location"))
    }

    @Step("Start authentication flow in TARA")
    static Response startAuthProcessInTara(Flow flow, Response response) {
        String taraUrl =  response.then().extract().response().getHeader("location")

        Response authenticationResponse = Requests.startAuthenticationFlowInTara(flow, taraUrl)
        String location = authenticationResponse.then().extract().response().getHeader("location")
        flow.setOauth2_authentication_csrf(authenticationResponse.getCookie("__Host-ory_hydra_login_csrf_1316479801"))
        URL locationUrl = new URL(location)
        String baseUrl = locationUrl.getProtocol() + "://" + (locationUrl.getPort() > 0 ? (":" + locationUrl.getPort()) : "") + locationUrl.getHost()
        flow.specificProxyService.setTaraBaseUrl(baseUrl)
        Response authInitResponse = Requests.followRedirect(flow, location)
        flow.setSessionId(authInitResponse.getCookie("SESSION"))
        flow.setCsrf(authInitResponse.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return authInitResponse
    }

    @Step("Authenticate with MID and follow redirects to consent")
    static Response authenticateWithMidAndFollowRedirects(Flow flow, Response taraLoginPageResponse) {
        MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)
        return Requests.submitAuthenticationAccept(flow, flow.specificProxyService.taraBaseUrl + "/auth/accept")
    }

    @Step("Select legal entity")
    static Response selectLegalEntity(Flow flow, String legalPersonId) {
        return Requests.selectLegalPerson(flow, flow.specificProxyService.taraBaseUrl + "/auth/legalperson/confirm", legalPersonId)
    }

    @Step("Display legal entity list")
    static Response getLegalEntityList(Flow flow, Response midAuthAcceptResponse) {
        Response response = Requests.submitLegalPersonInit(flow, flow.specificProxyService.taraBaseUrl + midAuthAcceptResponse.getHeader("location"))
        flow.setCsrf(response.body().htmlPath().get("**.find {it.@name == '_csrf'}.@value"))
        return Requests.getLegalPersonList(flow, flow.specificProxyService.taraBaseUrl + "/auth/legalperson")
    }

    @Step("User consents with authentication")
    static Response userConsentAndFollowRedirects(Flow flow, Response response) {
        Response response1 = Requests.followRedirectWithCsrfCookie(flow, response.getHeader("location"))
        flow.setOauth2_consent_csrf(response1.getCookie("__Host-ory_hydra_consent_csrf_1316479801"))
        Requests.followRedirect(flow, response1.getHeader("location"))

        Response response2 = Requests.consentSubmit(flow, flow.specificProxyService.taraBaseUrl + "/auth/consent/confirm", true)

        return Requests.followRedirectWithCsrfCookie(flow, response2.getHeader("location"))
    }

    @Step("User do not consent with authentication")
    static Response userDenyConsentAndFollowRedirects(Flow flow, Response response) {
        Response response1 = Requests.followRedirectWithCsrfCookie(flow, response.getHeader("location"))
        flow.setOauth2_consent_csrf(response1.getCookie("__Host-ory_hydra_consent_csrf_1316479801"))
        Requests.followRedirect(flow, response1.getHeader("location"))

        Response response2 = Requests.consentSubmit(flow, flow.specificProxyService.taraBaseUrl + "/auth/consent/confirm", false)

        return Requests.followRedirectWithCsrfCookie(flow, response2.getHeader("location"))
    }

    @Step("User cancels authentication")
    static Response userCancelAndFollowRedirects(Flow flow) {
        String returnUrl = flow.specificProxyService.taraBaseUrl + "/auth/reject?error_code=user_cancel"

        Response cancelResponse = Requests.backToServiceProvider(flow, returnUrl)
        String backToSpUrl = cancelResponse.then().extract().response().getHeader("location")
        return Requests.followRedirect(flow, backToSpUrl)
    }
}
