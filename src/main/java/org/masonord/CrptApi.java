package org.masonord;

import com.google.gson.Gson;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
public class CrptApi {
    private static final String createDocumentUrl = "https://ismp.crpt.ru/api/v3/lk/documents/create";

    /**
     * RateLimiter, as the name suggest, is created to limit amount of request per each tread
     */

    class RateLimiter {
        private final int REQUEST_LIMIT;
        private final long TIME_LIMIT;
        private final Map<String, Queue<Long>> clientHitQ;

        RateLimiter(long timeLimit, int requestLimit) {
            this.REQUEST_LIMIT = requestLimit;
            this.TIME_LIMIT = timeLimit;
            this.clientHitQ = new ConcurrentHashMap<>();
        }
        public synchronized boolean isAllow(String client_id) {
            Queue<Long> q = clientHitQ.get(client_id);
            long curTime = System.currentTimeMillis();
            if (q == null) {
                q = new LinkedList<Long>();
                clientHitQ.put(client_id, q);
            }
            while (!q.isEmpty() && curTime - q.peek() >= TIME_LIMIT) {
                q.poll();
            }

            if (q.size() < REQUEST_LIMIT) {
                q.offer(curTime);
                return true;
            }

            return false;
        }
    }

    /**
     * Environment class is responsible for fetching values from a properties file
     */

    class Environment {
        private static final Properties properties = new Properties();

        static {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            try (InputStream resourceStream = loader.getResourceAsStream("application.properties")) {
                properties.load(resourceStream);
            }catch(IOException e) {
                e.printStackTrace();
            }
        }

        public static String getValue(String key) {
            if (properties.containsKey(key)) {
                return properties.getProperty(key);
            }

            return "Value has not been found by the given key";
        }
    }

    class Authorization {
        private static final String certKeyUrl = "https://ismp.crpt.ru/api/v3/auth/cert/key";
        private static final String authCertUrl = "https://ismp.crpt.ru/api/v3/auth/cert/";
        private static final byte[] certificatePassword = Environment.getValue("certificate.password").getBytes();
        private static final String certificateName = Environment.getValue("certificate.name");
        private static class TokenResponse {
            private String encodedTokenBase64;

            public void setEncodedTokenBase64(String encodedTokenBase64) {
                this.encodedTokenBase64 = encodedTokenBase64;
            }

            public String getEncodedTokenBase64() {
                return encodedTokenBase64;
            }
        }

        private static class DataResponse {
            private String uuid;
            private String data;
            public void setData(String data) { this.data = data; }

            public void setUuid(String uuid) { this.uuid = uuid; }

            public String getUuid() { return uuid; }

            public String getData() { return data; }

        }

        private static class TokenRequest {
            private String uuid;
            private String data;

            public void setData(String data) { this.data = data; }

            public void setUuid(String uuid) { this.uuid = uuid; }

            public String getUuid() { return uuid; }

            public String getData() { return data; }

        }


        // -------------------------- Http Part --------------------------

        /**
         * Http Part
         *
         * The class is responsible for sending/accepting http requests and response
         * Particularly:
         *  - Get random uuid and data
         *  - Send obtained uuid and signed data
         *  - Get JWT authorization token
         *
         */

        class GetJwtToken {
            private static DataResponse getDataAndUuid() throws IOException, URISyntaxException, InterruptedException {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(new URI(certKeyUrl))
                        .GET()
                        .build();

                HttpResponse<String> response = HttpClient.newBuilder()
                        .build()
                        .send(request, HttpResponse.BodyHandlers.ofString());


                Gson gson = new Gson();
                DataResponse jsonResponse = gson.fromJson(response.body(), DataResponse.class);

                return jsonResponse;
            }

            private static TokenResponse getJWTToken(DataResponse dataResponse) throws URISyntaxException, IOException, InterruptedException {
                String signature = "dummy signature";

                TokenRequest tokenRequest = new TokenRequest();
                tokenRequest.setUuid(dataResponse.getUuid());
                tokenRequest.setData(signature);

                Gson gson = new Gson();

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(new URI(authCertUrl))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(tokenRequest)))
                        .build();

                HttpResponse<String> response = HttpClient.newBuilder()
                        .build()
                        .send(request, HttpResponse.BodyHandlers.ofString());

                return gson.fromJson(response.body(), TokenResponse.class);
            }
        }

        /**
         * Signature Part
         *
         * The class was initially created to signe a data by the chose certificate
         *
         */

        class Signature {
            private static X509Certificate getCertificate(String certificateName) throws  Exception {
                KeyStore keyStore = KeyStore.getInstance("Windows-MY");
                keyStore.load(null, null);

                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();

                    if (alias.equals(certificateName)) {
                        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                        return certificate;
                    }
                }

                throw new Exception("Certificate not found");

            }
            private static byte[] signMessage(byte[] message, X509Certificate certificate, PrivateKey privateKey) throws Exception {
                CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                        (DigestCalculatorProvider) new JcaCertStore(Collections.singletonList(certificate)))
                        .setDirectSignature(true)
                        .build((ContentSigner) privateKey, certificate));

                List<X509Certificate> certList = new ArrayList<>();
                certList.add(certificate);
                generator.addCertificates(new JcaCertStore(certList));

                CMSProcessableByteArray content = new CMSProcessableByteArray(message);
                CMSSignedData signedData = generator.generate(content, false);

                return signedData.getEncoded();
            }

            private static PrivateKey getPrivateKey(String aliasName, String password) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, IOException {
                KeyStore keyStore = KeyStore.getInstance("Windows-ROOT");
                keyStore.load(null, null);

                PrivateKey privateKey = (PrivateKey) keyStore.getKey(aliasName, password.toCharArray());

                if (privateKey != null)
                    return privateKey;

                throw new RuntimeException("Private has not been found");
            }
        }
    }

    public CrptApi(TimeUnit timeUnit, int requestLimit) {

    }

    public void createDocument(String document, String jwtToken) throws IOException, InterruptedException, URISyntaxException {
        Gson gson = new Gson();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(createDocumentUrl))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + jwtToken)
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(document)))
                .build();

        HttpResponse<String> response = HttpClient.newBuilder()
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString());
    }

    public static void main(String[] args) throws Exception {

    }
}