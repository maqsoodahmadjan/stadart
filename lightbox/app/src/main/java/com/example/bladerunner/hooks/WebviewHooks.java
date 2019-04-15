package com.example.bladerunner.hooks;

import android.util.Log;
import android.webkit.WebView;

import javax.crypto.Cipher;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class WebviewHooks extends GenericHooks {

    @Hook("android.webkit.WebView->loadUrl")
    public static void WebView_loadUrl(WebView wv, String s) {
        Log.d(TAG, "WebView_loadUrl url: " + s);
        OriginalMethod.by(new $() {}).invoke(wv,s);
    }
    @Hook("android.webkit.WebView->addJavascriptInterface")
    public static void WebView_addJavascriptInterface(Object o, String s) {
        Log.d(TAG, "WebView_addJavascriptInterface url: " + s);
        OriginalMethod.by(new $() {}).invoke(o,s);
    }
}
