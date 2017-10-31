package org.wso2.sp.migration.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.wso2.carbon.identity.sso.saml.stub.IdentitySAMLSSOConfigServiceStub;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderInfoDTO;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

/**
 * Service client to do SAML related SOAP operations.
 */
public class SAMLSSOConfigServiceClient {

    private IdentitySAMLSSOConfigServiceStub stub;

    public SAMLSSOConfigServiceClient(String cookie, String backendServerURL)
            throws AxisFault {
        try {
            String serviceURL = backendServerURL + "/services/IdentitySAMLSSOConfigService";
            stub = new IdentitySAMLSSOConfigServiceStub(serviceURL);
            ServiceClient client = stub._getServiceClient();
            Options option = client.getOptions();
            option.setManageSession(true);
            option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
        } catch (AxisFault ex) {
            throw new AxisFault("Error generating stub for IdentitySAMLSSOConfigService", ex);
        }
    }

    public boolean addServiceProvider(SAMLSSOServiceProviderDTO serviceProviderDTO) throws AxisFault {
        boolean status = false;
        try {
            status = stub.addRPServiceProvider(serviceProviderDTO);
        } catch (Exception e) {
            throw new AxisFault(e.getMessage(), e);
        }
        return status;
    }

    public SAMLSSOServiceProviderDTO getServiceProvider(String issuer) throws AxisFault {
        try {
            SAMLSSOServiceProviderInfoDTO dto = stub.getServiceProviders();
            SAMLSSOServiceProviderDTO[] sps = dto.getServiceProviders();
            if (sps != null) {
                for (SAMLSSOServiceProviderDTO sp : sps) {
                    if (sp.getIssuer().equals(issuer)) {
                        return sp;
                    }
                }
            }
        } catch (Exception e) {
            throw new AxisFault(e.getMessage(), e);
        }
        return null;

    }

    public SAMLSSOServiceProviderInfoDTO getRegisteredServiceProviders() throws AxisFault {
        try {
            SAMLSSOServiceProviderInfoDTO spInfo = stub.getServiceProviders();
            return spInfo;
        } catch (Exception e) {
            throw new AxisFault(e.getMessage(), e);
        }
    }

    public List<String> getCertAlias() throws AxisFault {
        List<String> certAliasList = new ArrayList<>();
        String[] certAliases;
        try {
            certAliases = stub.getCertAliasOfPrimaryKeyStore();
            for (String alias : certAliases) {
                certAliasList.add(alias);
            }
        } catch (Exception e) {
            throw new AxisFault(e.getMessage(), e);
        }
        return certAliasList;
    }

    public boolean removeServiceProvier(String issuerName) throws AxisFault {
        try {
            return stub.removeServiceProvider(issuerName);
        } catch (Exception e) {
            throw new AxisFault(e.getMessage(), e);
        }
    }

    public String[] getClaimURIs() throws AxisFault {
        String[] claimUris = null;
        try {
            claimUris = stub.getClaimURIs();
        } catch (Exception e) {
            throw new AxisFault(e.getMessage(), e);
        }
        return claimUris;
    }

    public String[] getSigningAlgorithmUris() throws RuntimeException {
        String[] signingAlgorithmUris;
        try {
            signingAlgorithmUris = stub.getSigningAlgorithmUris();
        } catch (RemoteException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        return signingAlgorithmUris;
    }

    public String getSigningAlgorithmUriByConfig() throws RuntimeException {
        String signingAlgo;
        try {
            signingAlgo = stub.getSigningAlgorithmUriByConfig();
        } catch (RemoteException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        return signingAlgo;
    }

    public String[] getDigestAlgorithmURIs() throws RuntimeException {
        String[] digestAlgorithms;
        try {
            digestAlgorithms = stub.getDigestAlgorithmURIs();
        } catch (RemoteException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        return digestAlgorithms;
    }

    public String getDigestAlgorithmURIByConfig() throws RuntimeException {
        String digestAlgo;
        try {
            digestAlgo = stub.getDigestAlgorithmURIByConfig();
        } catch (RemoteException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        return digestAlgo;
    }
}
