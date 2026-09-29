package ee.ria.specificproxyservice

class MidTestPerson {
    String idCode
    String phoneNumber
    String familyName
    String firstName
    String dateOfBirth
    String consentDateOfBirth

    String getEidasIdentifier() { "EE/CA/" + idCode }

    String getConsentIdentifier() { "EE" + idCode }

    @Override
    String toString() { idCode }

    static final MidTestPerson EE60001019906 = new MidTestPerson(
            idCode: "60001019906",
            phoneNumber: "00000766",
            familyName: "O’CONNEŽ-ŠUSLIK TESTNUMBER",
            firstName: "MARY ÄNN",
            dateOfBirth: "2000-01-01",
            consentDateOfBirth: "01.01.2000")
}
