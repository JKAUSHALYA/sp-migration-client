package org.wso2.sp.migration.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.authenticator.stub.LogoutAuthenticationExceptionException;

import java.rmi.RemoteException;

/**
 * Service client to log in to the Identity Server and get the authenticated cookie.
 */
public class LoginAdminServiceClient {

    private AuthenticationAdminStub authenticationAdminStub;

    public LoginAdminServiceClient(String backEndUrl) throws AxisFault {

        String endPoint = backEndUrl + "/services/AuthenticationAdmin";
        ConfigurationContext ctx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);
        authenticationAdminStub = new AuthenticationAdminStub(ctx, endPoint);
    }

    public String authenticate(String userName, String password) throws RemoteException,
            LoginAuthenticationExceptionException {

        String sessionCookie = null;

        if (authenticationAdminStub.login(userName, password, "localhost")) {
            ServiceContext serviceContext = authenticationAdminStub.
                    _getServiceClient().getLastOperationContext().getServiceContext();
            sessionCookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING);
        }

        return sessionCookie;
    }

    public void logOut() throws RemoteException, LogoutAuthenticationExceptionException {
        authenticationAdminStub.logout();
    }
}
