package org.wso2.sp.migration.client;

import org.apache.axis2.AxisFault;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.Priority;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.security.mgt.stub.keystore.xsd.CertData;
import org.wso2.carbon.security.mgt.stub.keystore.xsd.KeyStoreData;
import sun.security.x509.X509CertImpl;

import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Utility to migrate service providers between two WSO2 Identity Servers. Currently this util only support WSO2
 * Identity Server version 5.3.0 only.
 */
public class Client {

    private static final String KEY_STORE_TYPE = "key-store-type";
    private static final String KEY_STORE_PATH = "key-store-path";
    private static final String KEY_STORE_PASSWORD = "key-store-password";
    private static final String JAVAX_NET_SSL_TRUST_STORE = "javax.net.ssl.trustStore";
    private static final String JAVAX_NET_SSL_TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword";
    private static final String JAVAX_NET_SSL_TRUST_STORE_TYPE = "javax.net.ssl.trustStoreType";
    private static final String SOURCE_URL = "source-url";
    private static final String SOURCE_USERNAME = "source-username";
    private static final String SOURCE_PASSWORD = "source-password";
    private static final String SAMLSSO = "samlsso";
    private static final String OAUTH2 = "oauth2";
    private static final String DESTINATION_URL = "destination-url";
    private static final String DESTINATION_USERNAME = "destination-username";
    private static final String DESTINATION_PASSWORD = "destination-password";
    public static final String DESTINATION_KEYSTORE_NAME = "destination-keystore-name";

    private static Logger log;

    public static void main(String[] args) throws Exception {

        initializeLogger();

        if (args.length < 2) {
            log.error("Invalid number of arguments provided. Provide the service provider name and the properties " +
                    "file path.");
            return;
        }

        String propertiesFilePath = args[1];

        if (propertiesFilePath == null) {
            log.error("Unable to read the properties file path from command line arguments. Please enter the properties" +
                    " file path as the second command line argument.");
            return;
        }

        log.info("Starting the migration procedure.");

        Properties properties = new Properties();
        properties.load(new InputStreamReader(new FileInputStream(propertiesFilePath)));

        // Set the custom certificates.
        if (properties.getProperty(KEY_STORE_PATH) != null) {
            System.setProperty(JAVAX_NET_SSL_TRUST_STORE, properties.getProperty(KEY_STORE_PATH));
            System.setProperty(JAVAX_NET_SSL_TRUST_STORE_PASSWORD, properties.getProperty(KEY_STORE_PASSWORD));
            System.setProperty(JAVAX_NET_SSL_TRUST_STORE_TYPE, properties.getProperty(KEY_STORE_TYPE));
        }

        String sourceUrl = properties.getProperty(SOURCE_URL);
        String sourceUserName = properties.getProperty(SOURCE_USERNAME);
        String sourcePassword = properties.getProperty(SOURCE_PASSWORD);

        log.info("Source server URL is set to: " + sourceUrl);

        // Service provider name that we need to copy.
        String serviceProviderName = args[0];

        log.info("Reading information related to the service provider: " + serviceProviderName);

        // Connect to the source server and retrieve the given service provider information from that server.

        // Login to the source server and get the authenticate cookie.
        LoginAdminServiceClient sourceLoginAdminServiceClient = new LoginAdminServiceClient(sourceUrl);
        String authCookie = sourceLoginAdminServiceClient.authenticate(sourceUserName, sourcePassword);

        // Get the given service provider.
        ApplicationManagementServiceClient sourceApplicationManagementServiceClient =
                new ApplicationManagementServiceClient(authCookie, sourceUrl);
        ServiceProvider serviceProvider = sourceApplicationManagementServiceClient.getApplication(serviceProviderName);

        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = null;
        CertData certData = null;
        OAuthConsumerAppDTO oAuthConsumerAppDTO = null;

        for (InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig : serviceProvider
                .getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs()) {
            if (SAMLSSO.equals(inboundAuthenticationRequestConfig.getInboundAuthType())) {
                log.info("Reading SAML related information.");
                samlssoServiceProviderDTO = getSAMLApplication(authCookie, sourceUrl,
                        inboundAuthenticationRequestConfig.getInboundAuthKey());
                certData = getCertificate(authCookie, sourceUrl, samlssoServiceProviderDTO.getCertAlias());
            } else if (OAUTH2.equals(inboundAuthenticationRequestConfig.getInboundAuthType())) {
                log.info("Reading OAuth related information.");
                oAuthConsumerAppDTO = getOAuthApplication(authCookie, sourceUrl,
                        inboundAuthenticationRequestConfig.getInboundAuthKey());
            } else {
                log.warn("This util currently does not support migrating applications type of: " +
                        inboundAuthenticationRequestConfig.getInboundAuthType());
            }
        }

        // Logout from the source server.
        sourceLoginAdminServiceClient.logOut();

        log.info("Successfully completed reading information from source server.");

        // Connect to the destination server and add the service provider.

        String destinationUrl = properties.getProperty(DESTINATION_URL);
        String destinationUserName = properties.getProperty(DESTINATION_USERNAME);
        String destinationPassword = properties.getProperty(DESTINATION_PASSWORD);
        String destinationKeyStoreName = properties.getProperty(DESTINATION_KEYSTORE_NAME);

        log.info("Destination server URL is set to: " + destinationUrl);

        // Login to the destination server and get the authenticated cookie.
        LoginAdminServiceClient destinationLoginAdminServiceClient = new LoginAdminServiceClient(destinationUrl);
        authCookie = destinationLoginAdminServiceClient.authenticate(destinationUserName, destinationPassword);

        // Add the previously took service provider to the destination server.
        ApplicationManagementServiceClient destinationApplicationManagementServiceClient =
                new ApplicationManagementServiceClient(authCookie, destinationUrl);

        // If there is a SAML app add it.
        if (samlssoServiceProviderDTO != null) {
            log.info("Adding SAML application.");
            addCertificate(authCookie, destinationUrl, certData, destinationKeyStoreName);
            addSAMLApplication(authCookie, destinationUrl, samlssoServiceProviderDTO);
        }

        // If there is a OAuthe app add it.
        if (oAuthConsumerAppDTO != null) {
            log.info("Adding OAuth application.");
            addOAuthApplication(authCookie, destinationUrl, oAuthConsumerAppDTO);
        }

        destinationApplicationManagementServiceClient.createApplication(serviceProvider);
        int applicationId = destinationApplicationManagementServiceClient.getApplication(serviceProvider
                .getApplicationName()).getApplicationID();

        serviceProvider.setApplicationID(applicationId);
        destinationApplicationManagementServiceClient.updateApplicationData(serviceProvider);

        // Logout from destination server.
        destinationLoginAdminServiceClient.logOut();

        log.info("Service provider successfully migrated.");
    }

    private static void addSAMLApplication(String authCookie, String destinationUrl,
                                           SAMLSSOServiceProviderDTO samlssoServiceProviderDTO) throws AxisFault {

        SAMLSSOConfigServiceClient samlssoConfigServiceClient = new SAMLSSOConfigServiceClient(authCookie,
                destinationUrl);
        samlssoConfigServiceClient.addServiceProvider(samlssoServiceProviderDTO);
    }

    private static void addCertificate(String authCookie, String destinationUrl, CertData certData,
                                       String destinationKeyStoreName) throws Exception {

        KeyStoreAdminClient keyStoreAdminClient = new KeyStoreAdminClient(authCookie, destinationUrl);

        X509Certificate x509Certificate = new X509CertImpl();


        byte[] publicKey = certData.getPublicKey().getBytes();
        String fileName = certData.getAlias();

        for (String keyStoreEntry : keyStoreAdminClient.getStoreEntries(destinationKeyStoreName)) {
            if (keyStoreEntry.equals(certData.getAlias())) {
                return;
            }
        }

        //keyStoreAdminClient.importCertToStore(fileName, publicKey, destinationKeyStoreName);
    }

    private static void addOAuthApplication(String authCookie, String destinationUrl,
                                            OAuthConsumerAppDTO oAuthConsumerAppDTO) throws Exception {

        OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(authCookie, destinationUrl);
        oAuthAdminClient.registerOAuthApplicationData(oAuthConsumerAppDTO);
    }

    private static SAMLSSOServiceProviderDTO getSAMLApplication(String authCookie, String sourceUrl,
                                                                String inboundAuthKey)
            throws AxisFault {

        SAMLSSOConfigServiceClient samlssoConfigServiceClient = new SAMLSSOConfigServiceClient(authCookie, sourceUrl);
        return samlssoConfigServiceClient.getServiceProvider(inboundAuthKey);
    }

    private static CertData getCertificate(String cookie, String serverUrl, String certificateAlias) throws Exception {

        KeyStoreAdminClient keyStoreAdminClient = new KeyStoreAdminClient(cookie, serverUrl);
        KeyStoreData [] keyStoreData  = keyStoreAdminClient.getKeyStores();

        for (KeyStoreData keyStoreDatum : keyStoreData) {
            keyStoreDatum = keyStoreAdminClient.getKeystoreInfo(keyStoreDatum.getKeyStoreName());
            for (CertData certData : keyStoreDatum.getCerts()) {
                if (certData != null && certData.isAliasSpecified() && certificateAlias.equals(certData.getAlias())) {
                    return certData;
                }
            }
        }

        throw new Exception("Cannot find a certificate specified by the given alias in the key store.");
    }

    private static OAuthConsumerAppDTO getOAuthApplication(String cookie, String serverUrl, String consumerKey)
            throws Exception {

        OAuthAdminClient oAuthAdminClient = new OAuthAdminClient(cookie, serverUrl);
        return oAuthAdminClient.getOAuthApplicationData(consumerKey);
    }

    private static void initializeLogger () {

        PatternLayout layout = new PatternLayout("%-5p %d %m%n");
        ConsoleAppender consoleAppender = new ConsoleAppender(layout);
        consoleAppender.setName("sp-migration-app-console-appender");
        consoleAppender.setThreshold(Priority.INFO);
        consoleAppender.activateOptions();

        Logger.getRootLogger().addAppender(consoleAppender);
        log = Logger.getLogger(Client.class);
    }
}
