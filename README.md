<img src='doc/img/eu_regional_development_fund_horizontal.jpg' width="350" height="200">

# eIDAS Proxy integration tests

Tests for eIDAS proxy component (both eIDAS standard component and Estonia specific component)

## Prerequisites

1. SUT (eIDAS proxy) must be deployed. It must have TARA configured as identity provider
   
2. eIDAS connector metadata must be available. Either connector service must be deployed or metadata must be available through other means.
   
3. Fetch the tests:

`git clone https://github.com/e-gov/eIDAS-SpecificProxyService-Test.git`

## Configuring the test

1. Configure the properties file. 
   application.properties file needs to be either in `src/test/resources` directory or its location configured with .env file `src/test/resources`.
   Example of .env file:
   
```
configuration_base_path=/home/me/IdeaProjects/specificproxy-configuration
configuration_path=dev-local
```   

The example application.properties file with values are given ../src/test/resource/sample_application.properties

Description of values:

**specificproxyservice** - configuration parameters for the SUT (Estonian implementation of eIDAS proxy service)

**connector** - configuration parameters for tests who advertise themselves as DEMO-SP-CA connector.

| Parameter | Default |  Description |
|------------|--------------|------------|
| specificproxyservice.protocol | https  | Service protocol. | 
| specificproxyservice.host | ee-eidas-proxy  | Service URL. | 
| specificproxyservice.port | 8083  | Service port. | 
| specificproxyservice.metadataUrl | /EidasNode/ServiceMetadata  | Service metadata endpoint. | 
| specificproxyservice.authenticationRequestUrl | /EidasNode/ColleagueRequest  | Service authentication start endpoint. | 
| specificproxyservice.consentUrl | /SpecificProxyService/Consent  | Consent endpoint. | 
| specificproxyservice.heartbeatUrl | /SpecificProxyService/heartbeat  | Heartbeat endpoint. | 
| connector.protocol | https  | Service protocol. | 
| connector.host | ca-eidas-connector  | Service URL. | 
| connector.port | 8080  | Service port. | 
| connector.metadataUrl | /EidasNode/ConnectorMetadata  | Service metadata endpoint. | 
| connector.authenticationResponseUrl | /EidasNode/ColleagueResponse  | Service authentication response endpoint. | 
| connector.keystore.file | eidasKeyStore_Connector_CA.jks  | Keystore with request signing key. | 
| connector.keystore.password | local-demo  | Keystore password. | 
| connector.keystore.requestSigningKeyId | speps-ca-demo-certificate  | Key id for request signing | 
| connector.keystore.requestSigningKeyPassword | local-demo  | Request signing key password. | 
| connector.encryption.keystore.file | ca-connector-encryption.jks  | Keystore with response decryption key. | 
| connector.encryption.keystore.password | local-demo  | Keystore password. | 
| connector.encryption.keystore.requestEncryptionKeyId | ca-connector-encryption  | Key id for response decryption. | 
| connector.encryption.keystore.requestEncryptionKeyPassword | local-demo  | Response decryption key password. | 
| connector.truststore.file | tls-truststore.p12  | TLS truststore. | 
| connector.truststore.password | changeit  | TLS truststore password. | 

## Execute tests and generate report

1. To run the tests execute:

`./mvnw clean test`

2. To check the results:

a) Surefire plugin generates reports in ../target/surefire-reports folder.

b) For a comprehensive report, Allure is required ([instructions for download.](https://docs.qameta.io/allure/#_installing_a_commandline)). To generate the report execute:

`allure serve .../eidas-connector-test/allure-results/`

## To see Allure report after running tests in IntelliJ 

Configure correct Allure results directory in IntelliJ in order to view Allure report when running tests from IntelliJ

`Run-> Edit configurations-> Templates-> JUnit-> VM Options: -ea -Dallure.results.directory=$ProjectFileDir$/target/allure-results`

And delete all existing run configurations
