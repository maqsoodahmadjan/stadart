package com.example.bladerunner.hooks;

import android.app.Activity;
import android.util.Log;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class HttpHooks extends GenericHooks{

    @Hook("java.net.HttpURLConnection-><init>")
    public static void HttpURLConnection_init(HttpURLConnection a, URL u) {
        Log.d(TAG, "HttpURLConnection_init url: " + u);
        OriginalMethod.by(new $() {}).invoke(a, u);
    }
/*
    @Hook("com.android.okhttp.internal.http.HttpURLConnectionImpl->getOutputStream")
    public static OutputStream HttpURLConnectionImpl_getOutputStream(HttpURLConnection a) {
        Log.d(TAG, "HttpURLConnectionImpl_getOutputStream");
        return OriginalMethod.by(new $() {}).invoke(a);
    }
    @Hook("com.squareup.okhttp.internal.huc.HttpURLConnectionImpl->getOutputStream")
    public static OutputStream HttpURLConnectionImpl2_getOutputStream(HttpURLConnection a) {
        Log.d(TAG, "HttpURLConnectionImpl2_getOutputStream" );
        return OriginalMethod.by(new $() {}).invoke(a);
    }
*/
}
