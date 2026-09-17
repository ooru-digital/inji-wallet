package io.mosip.residentapp.jsonld;

import android.content.Context;
import android.util.Log;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.jsonld.loader.SchemeRouter;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

/**
 * Serves bundled W3C VC v2 / v1 and LDP proof contexts, and fetches other
 * contexts (issuer schemas) with {@code Accept: application/ld+json}.
 * Installed on both {@link ConfigurableDocumentLoader} and Titanium's
 * {@link SchemeRouter} so OpenID4VP URDNA2015 (VP + proof) can expand v2
 * credentials without a remote W3C fetch.
 */
public final class BundledJsonLdDocumentLoader implements DocumentLoader {

    private static final String TAG = "JsonLdDocumentLoader";
    private static final String ACCEPT_HEADER =
            "application/ld+json, application/json;q=0.9, */*;q=0.1";
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_MS = 15000;
    private static final int MAX_REDIRECTS = 8;

    private final Map<URI, Document> bundled = new HashMap<>();
    private final Map<URI, Document> remoteCache = new ConcurrentHashMap<>();

    public BundledJsonLdDocumentLoader(Context context) {
        Context appContext = context.getApplicationContext();
        putAsset(appContext, "https://www.w3.org/ns/credentials/v2", "credentials-v2.json");
        putAsset(appContext, "https://www.w3.org/ns/credentials/v2.jsonld", "credentials-v2.json");
        putAsset(appContext, "https://www.w3.org/2018/credentials/v1", "credentials-v1.json");
        putAsset(appContext, "https://www.w3.org/2018/credentials/v1.jsonld", "credentials-v1.json");
        putAsset(appContext, "http://www.w3.org/2018/credentials/v1", "credentials-v1.json");
        putAsset(appContext, "https://w3id.org/security/suites/jws-2020/v1", "jws-2020-v1.json");
        putAsset(appContext, "https://w3id.org/security/suites/ed25519-2020/v1", "ed25519-2020-v1.json");
        putAsset(appContext, "https://w3id.org/security/v1", "security-v1.json");
        putAsset(appContext, "https://w3id.org/security/v2", "security-v2.json");
        putAsset(appContext, "https://w3id.org/security/v3", "security-v3.json");
        putAsset(appContext, "http://w3id.org/security/v3", "security-v3.json");
        putAsset(
                appContext,
                "https://schema.credissuer.com/templates/NationalIdentityCredential/context.json",
                "credissuer-national-identity.json");
        bundled.putAll(info.weboftrust.ldsignatures.jsonld.LDSecurityContexts.CONTEXTS);
    }

    public static synchronized void install(Context context) {
        BundledJsonLdDocumentLoader loader = new BundledJsonLdDocumentLoader(context);
        ConfigurableDocumentLoader.setDefaultHttpLoader(loader);

        DocumentLoader defaultLoader = ConfigurableDocumentLoader.DOCUMENT_LOADER;
        if (defaultLoader instanceof ConfigurableDocumentLoader configurable) {
            configurable.setEnableHttp(true);
            configurable.setEnableHttps(true);
            configurable.setHttpLoader(loader);
        }

        DocumentLoader router = SchemeRouter.defaultInstance();
        if (router instanceof SchemeRouter schemeRouter) {
            schemeRouter.set("http", loader);
            schemeRouter.set("https", loader);
        }
    }

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        URI key = normalize(url);
        Document local = bundled.get(key);
        if (local != null) {
            return local;
        }
        Document cached = remoteCache.get(key);
        if (cached != null) {
            return cached;
        }
        try {
            Document fetched = fetchRemote(url);
            remoteCache.put(key, fetched);
            return fetched;
        } catch (JsonLdError e) {
            Log.e(TAG, "Failed to load JSON-LD context: " + url, e);
            throw e;
        }
    }

    private void putAsset(Context context, String url, String assetName) {
        try (InputStream in = context.getAssets().open(assetName)) {
            URI uri = URI.create(url);
            JsonDocument document = JsonDocument.of(MediaType.JSON_LD, in);
            document.setDocumentUrl(uri);
            bundled.put(uri, document);
        } catch (IOException | JsonLdError e) {
            throw new IllegalStateException("Failed to load bundled JSON-LD context " + url, e);
        }
    }

    private Document fetchRemote(URI url) throws JsonLdError {
        URI current = url;
        HttpURLConnection connection = null;
        try {
            for (int i = 0; i < MAX_REDIRECTS; i++) {
                connection = open(current);
                int status = connection.getResponseCode();
                if (status >= 300 && status < 400) {
                    String location = connection.getHeaderField("Location");
                    connection.disconnect();
                    connection = null;
                    if (location == null || location.isEmpty()) {
                        break;
                    }
                    current = current.resolve(location);
                    continue;
                }
                if (status >= 200 && status < 300) {
                    try (InputStream in = connection.getInputStream()) {
                        JsonDocument document = JsonDocument.of(MediaType.JSON_LD, in);
                        document.setDocumentUrl(url);
                        return document;
                    }
                }
                throw new JsonLdError(
                        JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                        "HTTP " + status + " loading " + url);
            }
            throw new JsonLdError(
                    JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                    "Too many redirects loading " + url);
        } catch (JsonLdError e) {
            throw e;
        } catch (Exception e) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED, e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static HttpURLConnection open(URI uri) throws IOException {
        URL url = uri.toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
        connection.setReadTimeout(READ_TIMEOUT_MS);
        connection.setRequestProperty("Accept", ACCEPT_HEADER);
        connection.setRequestProperty("User-Agent", "inji-wallet-jsonld");
        return connection;
    }

    private static URI normalize(URI url) {
        try {
            String path = url.getPath();
            if (path != null && path.endsWith("/") && path.length() > 1) {
                path = path.substring(0, path.length() - 1);
            }
            return new URI(url.getScheme(), url.getAuthority(), path, url.getQuery(), null);
        } catch (URISyntaxException e) {
            return url;
        }
    }
}
