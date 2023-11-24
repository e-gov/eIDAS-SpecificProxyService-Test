package ee.ria.specificproxyservice

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.response.Response

import static io.restassured.RestAssured.config
import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class Requests {
    @Step("GET metadata")
    static String getMetadataBody(String metadataUrl) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(metadataUrl)
                .then()
                .statusCode(200)
                .extract().body().asString()
    }

    @Step("GET heartbeat")
    static Response getHeartbeat(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.specificProxyService.fullheartbeatUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("POST to colleagueRequest")
    static Response colleagueRequest(Flow flow, String samlRequest) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("SAMLRequest", samlRequest)
                        .formParam("RelayState", "")
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(flow.specificProxyService.fullAuthenticationRequestUrl)
                        .then()
                        .extract().response()
    }

    @Step("GET to idpResponse")
    static Response idpResponse(Flow flow, String url) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(url)
                        .then()
                        .extract().response()
    }

    @Step("GET to specificProxyResponse")
    static Response specificProxyResponse(Flow flow, String url) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .get(url)
                        .then()
                        .extract().response()
    }

    @Step("POST to proxyServiceRequest")
    static Response proxyServiceRequest(Flow flow, String action, String token) {
        return  given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("token", token)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(action)
                        .then()
                        .extract().response()
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Follow redirect with CSRF cookies")
    static Response followRedirectWithCsrfCookie(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .cookie("__Host-ory_hydra_login_csrf_1316479801", flow.oauth2_authentication_csrf)
                .cookie("__Host-ory_hydra_consent_csrf_1316479801", flow.oauth2_consent_csrf)
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Start TARA authentication flow")
    static Response startAuthenticationFlowInTara(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Submit authentication accept")
    static Response submitAuthenticationAccept(Flow flow, String url) {
         return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .cookie("SESSION", flow.sessionId)
                        .formParam("_csrf", flow.csrf)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .post(url)
                        .then()
                        .extract().response()
    }

    @Step("Init legal person selection")
    static Response submitLegalPersonInit(Flow flow, String url) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .cookie("SESSION", flow.sessionId)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(url)
                        .then()
                        .extract().response()
    }

    @Step("Retrieve legal person representation list")
    static Response getLegalPersonList(Flow flow, String url) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .cookie("SESSION", flow.sessionId)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(url)
                        .then()
                        .extract().response()
    }

    @Step("Submit legal person selection")
    static Response selectLegalPerson(Flow flow, String url, String legalPersonId) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .cookie("SESSION", flow.sessionId)
                        .formParam("_csrf", flow.csrf)
                        .formParam("legal_person_identifier", legalPersonId)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .post(url)
                        .then()
                        .extract().response()
    }

    @Step("Consent Submit")
    static Response consentSubmit(Flow flow, String url, Boolean consentGiven) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .queryParam("consent_given", consentGiven)
                        .cookie("SESSION", flow.sessionId)
                        .formParam("_csrf", flow.csrf)
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .post(url)
                        .then().log().cookies()
                        .extract().response()
    }

    @Step("Return to service provider without authentication")
    static Response backToServiceProvider(Flow flow, String url) {
        return given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .config(RestAssured.config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .get(url)
                        .then()
                        .extract().response()
    }
}
