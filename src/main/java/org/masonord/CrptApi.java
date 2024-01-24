package org.masonord;

import com.google.gson.Gson;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

public class CrptApi {
    private static final String createDocumentUrl = "https://ismp.crpt.ru/api/v3/lk/documents/create";
    private static final long requestLimit = Long.parseLong(Environment.getValue("request.limit"));
    private static final long refillPeriod = Long.parseLong(Environment.getValue("refill.period"));
    private static TokenBucketRateLimiter rateLimiter;
    private static String signature;

    /**
     * The TokenBucketRateLimiter, as the name suggests, is created to limit the number of requests per tread
     */

    static class TokenBucketRateLimiter {
        private final long capacity;
        private final AtomicLong tokens;
        private final Duration refillPeriod;
        private volatile Instant lastRefillTime;

        public TokenBucketRateLimiter(long capacity, Duration refillPeriod) {
            this.capacity = capacity;
            this.tokens = new AtomicLong(capacity);
            this.refillPeriod = refillPeriod;
            this.lastRefillTime = Instant.now();
        }

        public synchronized boolean isAllowed() {
            refillTokens();

            long currentTokens = tokens.get();
            if (currentTokens > 0) {
                tokens.decrementAndGet();
                return true;
            }

            return false;
        }

        private synchronized void refillTokens() {
            Instant now = Instant.now();
            long timeElapsed = Duration.between(lastRefillTime, now).toMillis();
            long tokensToAdd = timeElapsed / refillPeriod.toMillis();

            if (tokensToAdd > 0) {
                lastRefillTime = now;
                tokens.getAndUpdate(currentTokens -> Math.min(capacity, currentTokens + tokensToAdd));
            }
        }
    }

    /**
     * The environment class is responsible for fetching values from a properties file.
     */

    static class Environment {
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

    /**
     *
     * The authorization class takes care of delivering the JWT authorization token.
     *
     */

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

        /**
         * Http Part
         *
         *  The class is responsible for sending and accepting HTTP requests and responses.
         *  Particularly:
         *      - Get random uuids and data.
         *      - Send obtained uuid and signed data.
         *      - Get a JWT authorization token.
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

            private static TokenResponse getJWTToken(DataResponse dataResponse) throws Exception {
                byte[] byteSignature = MakeSignature.signMessage(
                        dataResponse.getData().getBytes(),
                        MakeSignature.getCertificate(certificateName),
                        MakeSignature.getPrivateKey(certificateName, certificatePassword)
                );
                signature = Base64.getEncoder().encodeToString(byteSignature);

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
         * The class was initially created to sign a data by the chose certificate
         *
         */

        class MakeSignature {
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

                throw new RuntimeException("Certificate not found");
            }

            private static PrivateKey getPrivateKey(String aliasName, byte[] password) throws Exception {
                KeyStore keyStore = KeyStore.getInstance("Windows-MY");
                keyStore.load(null, null);

                PrivateKey privateKey = (PrivateKey) keyStore.getKey(aliasName, null);

                if (privateKey != null)
                    return privateKey;

                throw new RuntimeException("Private has not been found");
            }

            private static byte[] signMessage(byte[] message, X509Certificate certificate, PrivateKey privateKey) throws Exception {
                KeyStore keyStore = KeyStore.getInstance("Windows-MY");
                keyStore.load(null, null);

                Provider p = keyStore.getProvider();
                Signature sig = Signature.getInstance("SH1withRSA", p);
                sig.initSign(privateKey);
                sig.update(message);

                return sig.sign();
            }
        }
    }

    static class CreateDocumentRequest {
        String document_format;
        String product_document;
        String product_group;
        String signature;
        String type;


        public String getDocument_format() {
            return document_format;
        }

        public String getProduct_document() {
            return product_document;
        }

        public String getProduct_group() {
            return product_group;
        }

        public String getSignature() {
            return signature;
        }

        public String getType() {
            return type;
        }

        public void setDocument_format(String document_format) {
            this.document_format = document_format;
        }

        public void setProduct_document(String product_document) {
            this.product_document = product_document;
        }

        public void setProduct_group(String product_group) {
            this.product_group = product_group;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }

        public void setType(String type) {
            this.type = type;
        }
    }

    public CrptApi() {
        rateLimiter = new TokenBucketRateLimiter(
                requestLimit,
                Duration.ofSeconds(refillPeriod)
        );
    }

    public static void createDocument(CreateDocumentRequest document, String jwtToken) throws IOException, InterruptedException, URISyntaxException {
        if (rateLimiter.isAllowed()) {
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

        System.out.println("Too Many Request !!!");

    }

    public static void main(String[] args) throws Exception {
        CrptApi api = new CrptApi();
        CreateDocumentRequest newDocument = new CreateDocumentRequest();
        newDocument.setDocument_format("json");
        newDocument.setProduct_document("product 1");
        newDocument.setType("AGGREGATION_DOCUMENT");
        newDocument.setProduct_group("group 1");
        newDocument.setSignature(signature);

        createDocument(
                newDocument,
                Authorization.GetJwtToken.getJWTToken(
                        Authorization.GetJwtToken.getDataAndUuid()
                ).encodedTokenBase64
        );
    }
}