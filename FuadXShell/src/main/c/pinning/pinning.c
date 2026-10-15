#include <pinning.h>
#include <../reflection/reflection.h>

const char *fingerprintPerLevel[] =
{
    "30363D4AE4E1DE24AD25735292A006B1BFEBEE67C89536E493C6BB0B2226A482",
    "76E9E288AAFC0E37F4390CBF946AAD997D5C1C901B3CE513D3D8FADBABE2AB85",
    "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6"
};
const char * subjectPerLevel[][2] =
{
    { "api.stackexchange.com", "E6" },
    { "E6", "ISRG Root X1" },
    { "ISRG Root X1", "ISRG Root X1" }
};

ATTRIBUTES(always_inline, used)
static inline void *check_pinning(ATTRIBUTES(unused) void *arg)
{
    SSL_CTX *sslCtx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;
    X509 *certArray[2] = { NULL, NULL };
    X509 *cert = NULL;
    X509_NAME *subjectName = NULL;
    X509_NAME *issuerName = NULL;
    struct stack_st_X509 *chain = NULL;
    struct stack_st_X509 *fullChain = NULL;
    char targetHost[256] = { 0 };
    char subjectCN[256] = { 0 };
    char issuerCN[256] = { 0 };
    uint8_t trustedCertLevel[3] = { PINNING_UNKNOWN, PINNING_UNKNOWN, PINNING_UNKNOWN };
    ssize_t bytesWritten;

    sys_prctl(PR_SET_NAME, (unsigned long)"CheckPinningThrd\0", 0, 0, 0);
    /* Init SSL Library */
    SSL_library_init();
    SSL_load_error_strings();
    /* Create SSL Context */
    sslCtx = SSL_CTX_new(TLS_client_method());
    if (!sslCtx)
    {
        FUADXSHELL_LOG_E("Failed to create SSL context");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to create SSL context while performing Pinning check");
        return (void *)(intptr_t)(PINNING_UNKNOWN);
    }
    /* Disable verification */
    SSL_CTX_set_verify(sslCtx, SSL_VERIFY_NONE, NULL);
    /* Create BIO */
    bytesWritten = snprintf(targetHost, sizeof(targetHost), "%s:%d", HOST, PORT);
    if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(targetHost))
    {
        FUADXSHELL_LOG_E("Failed to format target host");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to format target host while performing Pinning check");
        SSL_CTX_free(sslCtx);
        return (void *)(intptr_t)(PINNING_UNKNOWN);
    }
    bio = BIO_new_ssl_connect(sslCtx);
    if (!bio)
    {
        FUADXSHELL_LOG_E("Failed to create BIO");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to create BIO while performing Pinning check");
        SSL_CTX_free(sslCtx);
        return (void *)(intptr_t)(PINNING_UNKNOWN);
    }
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    /* Set the target host */
    if (BIO_set_conn_hostname(bio, targetHost) <= 0)
    {
        FUADXSHELL_LOG_E("Failed to set connection hostname");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to set connection hostname while performing Pinning check");
        BIO_free_all(bio);
        SSL_CTX_free(sslCtx);
        return (void *)(intptr_t)(PINNING_UNKNOWN);
    }
    SSL_set_tlsext_host_name(ssl, HOST);
    /* Connect to the server */
    if (BIO_do_connect(bio) <= 0 || BIO_do_handshake(bio) <= 0)
    {
        FUADXSHELL_LOG_E("Failed to connect or handshake");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to connect or handshake while performing Pinning check");
        BIO_free_all(bio);
        SSL_CTX_free(sslCtx);
        return (void *)(intptr_t)(PINNING_UNKNOWN);
    }
    /* Get the peer certificate */
    chain = SSL_get_peer_cert_chain(ssl);
    if (!chain)
    {
        FUADXSHELL_LOG_E("Failed to get peer certificate");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get peer certificates while performing Pinning check");
        BIO_free_all(bio);
        SSL_CTX_free(sslCtx);
        return (void *)(intptr_t)(PINNING_UNKNOWN);
    }
    /* Check the first certificate in the chain */
    if (sk_X509_num(chain) < 2)
    {
        FUADXSHELL_LOG_E("Insufficient certificates in chain for pinning check");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Insufficient certificates in chain for pinning check");
        BIO_free_all(bio);
        SSL_CTX_free(sslCtx);
        return (void *)(intptr_t)(PINNING_NO_CERTS);
    }
    if (sk_X509_num(chain) == 2)
    {
        FUADXSHELL_LOG_I("Filling certificate chain with missing root certificate");
        log_msg(LOG_LEVEL_INFO, NULL, NULL, "Filling certificate chain with missing root certificate");
        certArray[0] = sk_X509_value(chain, 0);
        certArray[1] = sk_X509_value(chain, 1);
        fullChain = fill_missing_cert(certArray, 2, 3);
        if (!fullChain)
        {
            FUADXSHELL_LOG_E("Failed to fill missing certificate");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to fill missing certificate while performing Pinning check");
            BIO_free_all(bio);
            SSL_CTX_free(sslCtx);
            return (void *)(intptr_t)(PINNING_UNKNOWN);
        }
        chain = fullChain;
    }
    /* It should be three certificates in the chain */
    for (int i = 0; i < 3; i++)
    {
        cert = sk_X509_value(chain, i);
        subjectName = X509_get_subject_name(cert);
        issuerName = X509_get_issuer_name(cert);
        if (!cert || !subjectName || !issuerName)
        {
            FUADXSHELL_LOG_E("Failed to get certificate from chain");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get certificate from chain while performing Pinning check");
            BIO_free_all(bio);
            SSL_CTX_free(sslCtx);
            return (void *)(intptr_t)(PINNING_UNKNOWN);
        }
        bytesWritten = X509_NAME_get_text_by_NID(subjectName, NID_commonName, subjectCN, sizeof(subjectCN));
        if (bytesWritten == 0 || bytesWritten < 0)
        {
            FUADXSHELL_LOG_E("Failed to get subject from certificate");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get subject from certificate while performing Pinning check");
            BIO_free_all(bio);
            SSL_CTX_free(sslCtx);
            return (void *)(intptr_t)(PINNING_UNKNOWN);
        }
        bytesWritten = X509_NAME_get_text_by_NID(issuerName, NID_commonName, issuerCN, sizeof(issuerCN));
        if (bytesWritten == 0 || bytesWritten < 0)
        {
            FUADXSHELL_LOG_E("Failed to get issuer from certificate");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get issuer from certificate while performing Pinning check");
            BIO_free_all(bio);
            SSL_CTX_free(sslCtx);
            return (void *)(intptr_t)(PINNING_UNKNOWN);
        }
        FUADXSHELL_LOG_D("Certificate %d: Subject: %s, Issuer: %s", i + 1, subjectCN, issuerCN);
        trustedCertLevel[i] = check_trusted_certs(subjectCN, issuerCN, cert);
        FUADXSHELL_LOG_D("Checking if certificate is trusted: %d", trustedCertLevel[i]);
    }
    return trustedCertLevel[0] != PINNING_OK || trustedCertLevel[1] != PINNING_OK || trustedCertLevel[2] != PINNING_OK ?
           (void *)(intptr_t)(PINNING_ERROR) : (void *)(intptr_t)(PINNING_OK);
}

ATTRIBUTES(always_inline, used)
static int check_trusted_certs(const char *subject, const char *issuer, X509 *derEncodedCert)
{
    char hash[EVP_MAX_MD_SIZE] = { 0 };
    char hexHash[EVP_MAX_MD_SIZE + 1] = { 0 };
    char buffer[512] = { 0 };
    uint32_t hashLen = 0;

    if (!subject || !issuer || !derEncodedCert)
    {
        FUADXSHELL_LOG_E("Invalid parameters provided for checking trusted certificates");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Invalid parameters provided for checking trusted certificates while performing Pinning check");
        return PINNING_ERROR;
    }
    if (!X509_digest(derEncodedCert, EVP_sha256(), (uint8_t *)hash, &hashLen) || hashLen != 32)
    {
        FUADXSHELL_LOG_E("Failed to compute certificate digest");
        set_heuristic(buffer, sizeof(buffer), "Failed to compute certificate digest. SHA-256 output was expected but got %zu bytes and %s", hashLen, hash);
        log_msg(LOG_LEVEL_ERROR, LOG_EVENT_PINNING, buffer, "Failed to compute certificate digest while performing Pinning check");
        return PINNING_ERROR;
    }
    bin_to_hex(hash, hexHash, hashLen);
    FUADXSHELL_LOG_D("Certificate hash: %s", hexHash);
    log_msg(LOG_LEVEL_DEBUG, NULL, NULL, "Certificate hash: %s", hexHash);
    for (int i = 0; i < 3; i++)
    {
        if (!strcmp(hexHash, fingerprintPerLevel[i]))
        {
            FUADXSHELL_LOG_D("Certificate matches trusted fingerprint at level %d. Checking against subject and issuer", i);
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Certificate matches trusted fingerprint at level %d: %s. Checking against subject and issuer", i, hexHash);
            if (strstr(subject, subjectPerLevel[i][0]) && strstr(issuer, subjectPerLevel[i][1]))
            {
                FUADXSHELL_LOG_I("Certificate is trusted at level %d", i);
                log_msg(LOG_LEVEL_INFO, NULL, NULL, "Certificate is trusted at level %d: %s", i, hexHash);
                return PINNING_OK;
            }
            else
            {
                FUADXSHELL_LOG_W("Certificate subject or issuer does not match expected values for level %d", i);
                log_msg(LOG_LEVEL_WARN, NULL, NULL, "Certificate subject or issuer does not match expected values for level %d: %s", i, hexHash);
                continue;
            }
        }
    }
    /* Default when no match is found */
    FUADXSHELL_LOG_E("Certificate does not match any trusted fingerprints");
    set_heuristic(buffer, sizeof(buffer), "Certificate does not match any trusted fingerprints while performing Pinning check");
    log_msg(LOG_LEVEL_ERROR, LOG_EVENT_PINNING, buffer, "Certificate does not match any trusted fingerprints while performing Pinning check");
    return PINNING_ERROR;
}

ATTRIBUTES(always_inline, used)
static inline struct stack_st_X509 *load_ca_store(void)
{
    BIO *bio = NULL;
    X509 *ca = NULL;
    DIR *d = NULL;
    struct dirent *entry = NULL;
    struct stack_st_X509 *caStore = NULL;
    char caCertPath[512] = { 0 };
    ssize_t bytesWritten;

    d = opendir("/system/etc/security/cacerts");
    if (!d)
    {
        FUADXSHELL_LOG_E("Failed to open CA store directory");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to open CA store directory while performing Pinning check");
        return NULL;
    }
    caStore = sk_X509_new_null();
    if (!caStore)
    {
        FUADXSHELL_LOG_E("Failed to create CA store");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to create CA store while performing Pinning check");
        closedir(d);
        return NULL;
    }
    while ((entry = readdir(d)))
    {
        if (entry->d_name[0] == '.' || !strcmp(entry->d_name, ".."))
            continue;
        bytesWritten = snprintf(caCertPath, sizeof(caCertPath), "/system/etc/security/cacerts/%s", entry->d_name);
        if (bytesWritten < 0 || (size_t)bytesWritten >= sizeof(caCertPath))
        {
            FUADXSHELL_LOG_E("Failed to format CA certificate path");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to format CA certificate path while performing Pinning check");
            sk_X509_free(caStore);
            closedir(d);
            return NULL;
        }
        bio = BIO_new_file(caCertPath, "r");
        if (!bio)
        {
            FUADXSHELL_LOG_W("Failed to open CA certificate file: %s. Continue", caCertPath);
            log_msg(LOG_LEVEL_WARN, NULL, NULL, "Failed to open CA certificate file. Continue");
            continue;
        }
        ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (ca)
            sk_X509_push(caStore, ca);
    }
    closedir(d);
    return caStore;
}

ATTRIBUTES(always_inline, used)
static inline struct stack_st_X509 *fill_missing_cert(X509 *certs[static 2], int certsCount,
                                                      ATTRIBUTES(unused) int levels)
{
    uint8_t isRootCertSent = 0;
    uint8_t isMiddleCertSent = 0;
    struct stack_st_X509 *caStore = NULL;
    struct stack_st_X509 *fullChain = NULL;
    struct stack_st_X509 *tmpChain = NULL;
    X509 *caCert = NULL;
    char *subjectName = NULL;

    if (certsCount > 2 || !(X509_NAME_cmp(X509_get_subject_name(certs[certsCount - 1]),
                                         X509_get_issuer_name(certs[certsCount - 1]))))
        isRootCertSent = 1;
    isMiddleCertSent = (certsCount > 1);
    caStore = load_ca_store();
    if (!caStore)
    {
        FUADXSHELL_LOG_E("Failed to load CA store. Unable to restore certificate chain");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to load CA store while performing Pinning check");
        return NULL;
    }
    fullChain = sk_X509_new_null();
    for (int i = 0; i < certsCount; i++)
    {
        X509_up_ref(certs[i]);
        sk_X509_push(fullChain, certs[i]);
    }
    for (int i = 0; i < sk_X509_num(caStore); i++)
    {
        caCert = sk_X509_value(caStore, i);
        subjectName = X509_NAME_oneline(X509_get_subject_name(caCert), NULL, 0);
        if (!subjectName)
        {
            FUADXSHELL_LOG_W("Failed to get subject name from CA certificate. Continue");
            log_msg(LOG_LEVEL_WARN, NULL, NULL, "Failed to get subject name from CA certificate. Continue");
            continue;
        }
        if (!isRootCertSent && strstr(subjectName, subjectPerLevel[2][0]))
        {
            FUADXSHELL_LOG_D("Found root certificate: %s", subjectName);
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Found root certificate to restore chain: %s", subjectName);
            X509_up_ref(caCert);
            sk_X509_push(fullChain, caCert);
            OPENSSL_free(subjectName);
            break;
        }
        if (!isMiddleCertSent && strstr(subjectName, subjectPerLevel[1][0]))
        {
            FUADXSHELL_LOG_D("Found intermediate certificate: %s", subjectName);
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Found intermediate certificate to restore chain: %s", subjectName);
            tmpChain = sk_X509_new_null();
            X509_up_ref(certs[0]);
            sk_X509_push(tmpChain, certs[0]);
            X509_up_ref(caCert);
            sk_X509_push(tmpChain, caCert);
            X509_up_ref(certs[1]);
            sk_X509_push(tmpChain, certs[1]);
            sk_X509_pop_free(fullChain, X509_free);
            fullChain = tmpChain;
            OPENSSL_free(subjectName);
            break;
        }
        OPENSSL_free(subjectName);
    }
    sk_X509_pop_free(caStore, X509_free);
    return fullChain;
}

ATTRIBUTES(always_inline, used)
static inline int check_internet_availability(JNIEnv *env, void *contextObj)
{
    void *connectivityManagerClass = NULL;
    void *connectivityManagerObject = NULL;
    void *getSystemServiceMethodId = NULL;
    void *networkCapabilitiesClass = NULL;
    void *networkCapabilitiesObject = NULL;
    void *activeNetworkObject = NULL;
    void *getNetworkCapabilitiesMethodId = NULL;
    void *getActiveNetworkMethodId = NULL;
    void *hasCapabilityMethodId = NULL;
    void *hasTransportMethodId = NULL;
    void *connectivityString = NULL;
    uint8_t hasCapInternet;
    uint8_t hasCapValidated;
    uint8_t hasTransportWifi;
    uint8_t hasTransportCellular;

    FUADXSHELL_LOG_D("Checking internet availability");
    connectivityManagerClass = getJNIClass(env, "android/net/ConnectivityManager");
    if (!connectivityManagerClass)
    {
        FUADXSHELL_LOG_E("Failed to get ConnectivityManager class");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get ConnectivityManager class while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    getSystemServiceMethodId = getJNIStaticMethodID(env, connectivityManagerClass, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (!getSystemServiceMethodId)
    {
        FUADXSHELL_LOG_E("Failed to get getSystemService method ID");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get getSystemService method ID while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    connectivityString = (*env)->NewStringUTF(env, CONNECTIVITY_SERVICE);
    if (!connectivityString)
    {
        FUADXSHELL_LOG_E("Failed to create connectivity string");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to create connectivity string while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    connectivityManagerObject = (*env)->CallObjectMethod(env, contextObj, getSystemServiceMethodId, connectivityString);
    if (!connectivityManagerObject)
    {
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while calling getSystemService");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get ConnectivityManager object while performing Pinning check");
            return TRANSPORT_UNAVAILABLE;
        }
        else
        {
            FUADXSHELL_LOG_E("Failed to get ConnectivityManager object");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get ConnectivityManager object while performing Pinning check");
            return TRANSPORT_UNAVAILABLE;
        }
    }
    networkCapabilitiesClass = getJNIClass(env, "android/net/NetworkCapabilities");
    if (!networkCapabilitiesClass)
    {
        FUADXSHELL_LOG_E("Failed to get NetworkCapabilities class");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get NetworkCapabilities class while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    getNetworkCapabilitiesMethodId = getJNIMethodID(env, connectivityManagerClass, "getNetworkCapabilities", "(Landroid/net/Network;)Landroid/net/NetworkCapabilities;");
    if (!getNetworkCapabilitiesMethodId)
    {
        FUADXSHELL_LOG_E("Failed to get getNetworkCapabilities method ID");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get getNetworkCapabilities method ID while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    getActiveNetworkMethodId = getJNIMethodID(env, connectivityManagerClass, "getActiveNetwork", "()Landroid/net/Network;");
    if (!getActiveNetworkMethodId)
    {
        FUADXSHELL_LOG_E("Failed to get getActiveNetwork method ID");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get getActiveNetwork method ID while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    activeNetworkObject = getJNIObject(env, connectivityManagerObject, getActiveNetworkMethodId);
    if (!activeNetworkObject)
    {
        FUADXSHELL_LOG_E("Failed to get active network object");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get active network object while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    networkCapabilitiesObject = (*env)->CallObjectMethod(env, connectivityManagerObject, getNetworkCapabilitiesMethodId, activeNetworkObject);
    if (!networkCapabilitiesObject)
    {
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while calling getNetworkCapabilities");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get NetworkCapabilities object while performing Pinning check");
            return TRANSPORT_UNAVAILABLE;
        }
        else
        {
            FUADXSHELL_LOG_E("Failed to get NetworkCapabilities object");
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get NetworkCapabilities object while performing Pinning check");
            return TRANSPORT_UNAVAILABLE;
        }
    }
    hasCapabilityMethodId = getJNIMethodID(env, networkCapabilitiesClass, "hasCapability", "(I)Z");
    if (!hasCapabilityMethodId)
    {
        FUADXSHELL_LOG_E("Failed to get hasCapability method ID");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get hasCapability method ID while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    hasTransportMethodId = getJNIMethodID(env, networkCapabilitiesClass, "hasTransport", "(I)Z");
    if (!hasTransportMethodId)
    {
        FUADXSHELL_LOG_E("Failed to get hasTransport method ID");
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Failed to get hasTransport method ID while performing Pinning check");
        return TRANSPORT_UNAVAILABLE;
    }
    hasCapInternet = (*env)->CallBooleanMethod(env, networkCapabilitiesObject, hasCapabilityMethodId, CAP_INTERNET);
    hasCapValidated = (*env)->CallBooleanMethod(env, networkCapabilitiesObject, hasCapabilityMethodId, CAP_VALIDATED);
    hasTransportWifi = (*env)->CallBooleanMethod(env, networkCapabilitiesObject, hasTransportMethodId, TRANSPORT_WIFI);
    hasTransportCellular = (*env)->CallBooleanMethod(env, networkCapabilitiesObject, hasTransportMethodId, TRANSPORT_CELLULAR);
    if (hasCapInternet && hasCapValidated)
    {
        if (hasTransportWifi)
        {
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Internet is available via WiFi");
            return TRANSPORT_WIFI;
        }
        else if (hasTransportCellular)
        {
            log_msg(LOG_LEVEL_INFO, NULL, NULL, "Internet is available via Cellular");
            return TRANSPORT_CELLULAR;
        }
        else
        {
            log_msg(LOG_LEVEL_ERROR, NULL, NULL, "No transport found");
            return TRANSPORT_UNAVAILABLE;
        }
    }
    log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Internet is not available or was not validated");
    return TRANSPORT_UNAVAILABLE;
}

ATTRIBUTES(always_inline, used)
int run_pinning(JNIEnv *env, void *contextObject)
{
    pthread_t pinningThread;
    intptr_t pinningResult = -1;

    FUADXSHELL_LOG_D("Checking internet availability");
    if (unlikely(check_internet_availability(env, contextObject) == -1))
    {
        FUADXSHELL_LOG_E("Internet is not available or was not validated");
        return PINNING_NO_NETWORK_AVAILABLE; /* Should default because it can't be validated nor denied */
    }
    FUADXSHELL_LOG_D("Checking pinning using OpenSSL");
    if (pthread_create(&pinningThread, NULL, (void *(*)(void *))check_pinning, NULL) != 0)
    {
        FUADXSHELL_LOG_E("Error while creating pinning thread: %s", strerror(errno));
        log_msg(LOG_LEVEL_ERROR, NULL, NULL, "Error while creating pinning thread: %s", strerror(errno));
        return PINNING_UNKNOWN;
    }
    pthread_join(pinningThread, (void **)&pinningResult);
    return pinningResult;
}