package com.example.bladerunner.hooks;

import android.util.Log;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class NetworkHooks extends GenericHooks {

    /*   at java.net.InetAddress.getAllByName(InetAddress.java:752) */
    @Hook("java.net.InetAddress->getAllByName")
    public static InetAddress[] InetAddress_getAllByName(String host) {
        Log.d(TAG, "InetAddress_getAllByName host: " + host);
        return OriginalMethod.by(new $() {}).invokeStatic(host);
    }
    @Hook("java.net.URL-><init>")
    public static void netURL(URL thiz, String spec){
        Log.d(TAG, "creating URL for : " + spec);
        OriginalMethod.by(new $() {}).invoke(thiz, spec);
    }
    @Hook("java.net.Socket-><init>")
    public static void mySocket(Socket thiz, String host, int port){
        Log.d(TAG, "creating socket to : " + host + " port: " + port);
        OriginalMethod.by(new $() {}).invoke(thiz, host,port);
    }
}
