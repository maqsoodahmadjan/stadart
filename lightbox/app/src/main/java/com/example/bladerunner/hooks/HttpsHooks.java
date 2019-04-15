package com.example.bladerunner.hooks;

import android.util.Log;

import java.net.HttpURLConnection;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class HttpsHooks extends GenericHooks{

    @Hook("javax.net.ssl.SSLContext->init")
    public static void SSLContext_init(SSLContext sslc, KeyManager[] km, TrustManager[] tm, SecureRandom sr ) {
        Log.d(TAG, "SSLContext_init called" );
        OriginalMethod.by(new $() {}).invoke(sslc, km, tm, sr);
    }

    @Hook("javax.net.ssl.HttpsURLConnection->setSSLSocketFactory")
    public static void URL_setSSLSocketFactory(SSLSocketFactory thiz, SSLSocketFactory sslf) {
        Log.d(TAG, "URL_setSSLSocketFactory called" );
        OriginalMethod.by(new $() {}).invoke(thiz, sslf);
    }
}
