package org.wso2.sp.migration.client;

import org.apache.axiom.om.util.Base64;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.security.mgt.stub.keystore.AddKeyStore;
import org.wso2.carbon.security.mgt.stub.keystore.DeleteStore;
import org.wso2.carbon.security.mgt.stub.keystore.GetKeyStoresResponse;
import org.wso2.carbon.security.mgt.stub.keystore.GetKeystoreInfo;
import org.wso2.carbon.security.mgt.stub.keystore.GetKeystoreInfoResponse;
import org.wso2.carbon.security.mgt.stub.keystore.GetPaginatedKeystoreInfo;
import org.wso2.carbon.security.mgt.stub.keystore.GetPaginatedKeystoreInfoResponse;
import org.wso2.carbon.security.mgt.stub.keystore.GetStoreEntries;
import org.wso2.carbon.security.mgt.stub.keystore.GetStoreEntriesResponse;
import org.wso2.carbon.security.mgt.stub.keystore.ImportCertToStore;
import org.wso2.carbon.security.mgt.stub.keystore.KeyStoreAdminServiceStub;
import org.wso2.carbon.security.mgt.stub.keystore.RemoveCertFromStore;
import org.wso2.carbon.security.mgt.stub.keystore.xsd.KeyStoreData;
import org.wso2.carbon.security.mgt.stub.keystore.xsd.PaginatedKeyStoreData;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Enumeration;

/**
 * Service client to Key Store related operations.
 */
public class KeyStoreAdminClient {

    private static Log log = LogFactory.getLog(KeyStoreAdminClient.class);
    private KeyStoreAdminServiceStub stub = null;

    public KeyStoreAdminClient(String cookie, String url)
            throws Exception {

        try {
            String serviceEndPoint = url + "/services/KeyStoreAdminService";
            this.stub = new KeyStoreAdminServiceStub(serviceEndPoint);
            ServiceClient client = stub._getServiceClient();
            Options option = client.getOptions();
            option.setManageSession(true);
            option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
        } catch (AxisFault e) {
            log.error("Error in creating KeyStoreAdminClient", e);
            throw e;
        }

    }

    public KeyStoreData[] getKeyStores() throws Exception {

        try {
            GetKeyStoresResponse response = stub.getKeyStores();
            return response.get_return();
        } catch (java.lang.Exception e) {
            log.error("Error in getting keystore data", e);
            throw e;
        }
    }

    public void addKeyStore(byte[] content, String filename, String password, String provider,
                            String type, String pvtkspass) throws Exception {

        try {
            String data = Base64.encode(content);
            AddKeyStore request = new AddKeyStore();
            request.setFileData(data);
            request.setFilename(filename);
            request.setPassword(password);
            request.setProvider(provider);
            request.setType(type);
            request.setPvtkeyPass(pvtkspass);
            stub.addKeyStore(request);
        } catch (java.lang.Exception e) {
            log.error("Error in adding keystore", e);
            throw e;
        }
    }

    public void deleteStore(String keyStoreName) throws Exception {

        try {
            DeleteStore request = new DeleteStore();
            request.setKeyStoreName(keyStoreName);
            stub.deleteStore(request);
        } catch (java.lang.Exception e) {
            log.error("Error in deleting keystore", e);
            throw e;
        }
    }

    public void importCertToStore(String filename, byte[] content, String keyStoreName)
            throws Exception {

        try {
            String data = Base64.encode(content);
            ImportCertToStore request = new ImportCertToStore();
            request.setFileName(filename);
            request.setFileData(data);
            request.setKeyStoreName(keyStoreName);
            stub.importCertToStore(request);
        } catch (java.lang.Exception e) {
            log.error("Error in importing cert to store.", e);
            throw e;
        }
    }

    public String[] getStoreEntries(String keyStoreName) throws Exception {

        try {
            GetStoreEntries request = new GetStoreEntries();
            request.setKeyStoreName(keyStoreName);
            GetStoreEntriesResponse response = stub.getStoreEntries(request);
            return response.get_return();
        } catch (java.lang.Exception e) {
            log.error("Error in getting store entries.", e);
            throw e;
        }
    }

    private byte[] getBytesFromFile(File file) throws Exception {

        InputStream is = new FileInputStream(file);
        try {
            // Get the size of the file
            long length = file.length();

            if (length > Integer.MAX_VALUE) {
                throw new IOException("File is too large");
            }

            // Create the byte array to hold the data
            byte[] bytes = new byte[(int) length];

            // Read in the bytes
            int offset = 0;
            int numRead = 0;
            while (offset < bytes.length
                    && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
                offset += numRead;
            }

            if (offset < bytes.length) {
                throw new IOException("Could not completely read file " + file.getName());
            }
            return bytes;
        } catch (java.lang.Exception e) {
            log.error("Error in getting bytes from file.", e);
            throw e;
        } finally {
            is.close();
        }
    }

    public boolean isPrivateKeyStore(byte[] content, String password, String type)
            throws Exception {

        try {
            boolean isPrivateStore = false;
            ByteArrayInputStream stream = new ByteArrayInputStream(content);
            KeyStore store = KeyStore.getInstance(type);
            store.load(stream, password.toCharArray());
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                String value = aliases.nextElement();
                if (store.isKeyEntry(value)) {
                    isPrivateStore = true;
                    break;
                }
            }
            return isPrivateStore;
        } catch (java.lang.Exception e) {
            log.error("Error in checking private key store.", e);
            throw e;
        }
    }

    public KeyStoreData getKeystoreInfo(String keyStoreName) throws java.lang.Exception {

        try {
            GetKeystoreInfo request = new GetKeystoreInfo();
            request.setKeyStoreName(keyStoreName);
            GetKeystoreInfoResponse response = stub.getKeystoreInfo(request);
            return response.get_return();
        } catch (java.lang.Exception e) {
            log.error("Error in getting keystore info.", e);
            throw e;
        }
    }

    public void removeCertificateFromKeyStore(String keySoreName, String CertificateAlias) throws Exception {

        RemoveCertFromStore request = new RemoveCertFromStore();
        request.setKeyStoreName(keySoreName);
        request.setAlias(CertificateAlias);
        try {
            stub.removeCertFromStore(request);
        } catch (java.lang.Exception e) {
            log.error("Error in removing certificate from keystore.", e);
            throw e;
        }
    }

    public PaginatedKeyStoreData getPaginatedKeystoreInfo(String keyStoreName, int pageNumber) throws Exception {

        try {
            GetPaginatedKeystoreInfo request = new GetPaginatedKeystoreInfo();
            request.setKeyStoreName(keyStoreName);
            request.setPageNumber(pageNumber);

            GetPaginatedKeystoreInfoResponse response = stub.getPaginatedKeystoreInfo(request);
            return response.get_return();
        } catch (java.lang.Exception e) {
            log.error("Error in getting paginated keystore info.", e);
            throw e;
        }
    }
}
