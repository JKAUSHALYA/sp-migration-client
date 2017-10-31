package org.wso2.sp.migration.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceStub;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthRevocationResponseDTO;

/**
 * Service client to do OAuth related SOAP operations.
 */
public class OAuthAdminClient {

    private static String[] allowedGrantTypes = null;
    private OAuthAdminServiceStub stub;

    /**
     * Instantiates OAuthAdminClient
     *
     * @param cookie           For session management
     * @param backendServerURL URL of the back end server where OAuthAdminService is running.
     * @throws org.apache.axis2.AxisFault
     */
    public OAuthAdminClient(String cookie, String backendServerURL)
            throws AxisFault {
        String serviceURL = backendServerURL + "/services/OAuthAdminService";
        stub = new OAuthAdminServiceStub(serviceURL);
        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
    }

    public OAuthConsumerAppDTO[] getAllOAuthApplicationData() throws Exception {
        return stub.getAllOAuthApplicationData();
    }

    public OAuthConsumerAppDTO getOAuthApplicationData(String consumerkey) throws Exception {
        return stub.getOAuthApplicationData(consumerkey);
    }

    public OAuthConsumerAppDTO getOAuthApplicationDataByAppName(String appName) throws Exception {
        return stub.getOAuthApplicationDataByAppName(appName);
    }

    public void registerOAuthApplicationData(OAuthConsumerAppDTO application) throws Exception {
        stub.registerOAuthApplicationData(application);
    }

    public OAuthConsumerAppDTO getOAuthApplicationDataByName(String applicationName) throws Exception {
        OAuthConsumerAppDTO[] dtos = stub.getAllOAuthApplicationData();
        if (dtos != null && dtos.length > 0) {
            for (OAuthConsumerAppDTO dto : dtos) {
                if (applicationName.equals(dto.getApplicationName())) {
                    return dto;
                }
            }
        }
        return null;
    }

    public void removeOAuthApplicationData(String consumerkey) throws Exception {
        stub.removeOAuthApplicationData(consumerkey);
    }

    public void updateOAuthApplicationData(OAuthConsumerAppDTO consumerAppDTO) throws Exception {
        stub.updateConsumerApplication(consumerAppDTO);
    }

    public OAuthConsumerAppDTO[] getAppsAuthorizedByUser() throws Exception {
        return stub.getAppsAuthorizedByUser();
    }

    public OAuthRevocationResponseDTO revokeAuthzForAppsByRessourceOwner(OAuthRevocationRequestDTO reqDTO)
            throws Exception {
        return stub.revokeAuthzForAppsByResoureOwner(reqDTO);
    }

    public boolean isPKCESupportedEnabled() throws Exception {
        return stub.isPKCESupportEnabled();
    }

    public String[] getAllowedOAuthGrantTypes() throws Exception {
        if (allowedGrantTypes == null) {
            allowedGrantTypes = stub.getAllowedGrantTypes();
        }
        return allowedGrantTypes;
    }

    public void regenerateSecretKey(String consumerkey) throws Exception {
        stub.updateOauthSecretKey(consumerkey);
    }

    public String getOauthApplicationState(String consumerKey) throws Exception {
        return stub.getOauthApplicationState(consumerKey);
    }

    public void updateOauthApplicationState(String consumerKey, String newState) throws Exception {
        stub.updateConsumerAppState(consumerKey, newState);
    }
}
