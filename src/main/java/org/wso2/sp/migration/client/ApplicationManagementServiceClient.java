package org.wso2.sp.migration.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.wso2.carbon.identity.application.common.model.xsd.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.xsd.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.xsd.LocalAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.xsd.RequestPathAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceIdentityApplicationManagementException;
import org.wso2.carbon.identity.application.mgt.stub.IdentityApplicationManagementServiceStub;

import java.rmi.RemoteException;

/**
 * Service client to do Application Management related SOAP operations.
 */
public class ApplicationManagementServiceClient {

    private IdentityApplicationManagementServiceStub stub;

    public ApplicationManagementServiceClient(String cookie, String backendServerURL) throws AxisFault {

        String serviceURL = backendServerURL + "/services/IdentityApplicationManagementService";
        stub = new IdentityApplicationManagementServiceStub(serviceURL);

        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
    }

    public void createApplication(ServiceProvider serviceProvider) throws AxisFault {
        try {
            stub.createApplication(serviceProvider);
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
    }

    public ServiceProvider getApplication(String applicationName) throws AxisFault {
        try {
            return stub.getApplication(applicationName);
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
        return null;
    }

    public ApplicationBasicInfo[] getAllApplicationBasicInfo() throws Exception {
        try {
            return stub.getAllApplicationBasicInfo();
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
        return new ApplicationBasicInfo[0];
    }

    public void updateApplicationData(ServiceProvider serviceProvider) throws Exception {
        try {
            stub.updateApplication(serviceProvider);
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
    }

    public void deleteApplication(String applicationID) throws Exception {
        try {
            stub.deleteApplication(applicationID);
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
    }

    public IdentityProvider getFederatedIdentityProvider(String identityProviderName) throws AxisFault {
        try {
            return stub.getIdentityProvider(identityProviderName);
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
        return null;
    }

    public RequestPathAuthenticatorConfig[] getAllRequestPathAuthenticators() throws AxisFault {
        try {
            return stub.getAllRequestPathAuthenticators();
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
        return new RequestPathAuthenticatorConfig[0];
    }

    public LocalAuthenticatorConfig[] getAllLocalAuthenticators() throws AxisFault {
        try {
            return stub.getAllLocalAuthenticators();
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
        return new LocalAuthenticatorConfig[0];
    }

    public IdentityProvider[] getAllFederatedIdentityProvider() throws AxisFault {
        try {
            return stub.getAllIdentityProviders();
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
        return new IdentityProvider[0];
    }

    public String[] getAllClaimUris() throws AxisFault {
        try {
            return stub.getAllLocalClaimUris();
        } catch (RemoteException | IdentityApplicationManagementServiceIdentityApplicationManagementException e) {
            handleException(e);
        }
        return new String[0];
    }

    private void handleException(Exception e) throws AxisFault {

        String errorMessage = "Unknown error occurred.";

        if (e instanceof IdentityApplicationManagementServiceIdentityApplicationManagementException) {
            IdentityApplicationManagementServiceIdentityApplicationManagementException exception =
                    (IdentityApplicationManagementServiceIdentityApplicationManagementException) e;
            if (exception.getFaultMessage().getIdentityApplicationManagementException() != null) {
                errorMessage = exception.getFaultMessage().getIdentityApplicationManagementException().getMessage();
            }
        } else {
            errorMessage = e.getMessage();
        }

        throw new AxisFault(errorMessage, e);
    }
}
