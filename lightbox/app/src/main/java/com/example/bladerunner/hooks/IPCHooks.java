package com.example.bladerunner.hooks;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import java.net.HttpURLConnection;
import java.net.URL;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class IPCHooks extends GenericHooks{

    @Hook("android.app.Activity->startActivity")
    public static void Activity_startActivity(Activity a, Intent i, Bundle b) {
        Log.d(TAG, "Activity_startActivity");
        Intent intent = (Intent) i;
        Log.d(TAG ,"startActivity: "+intent);
        OriginalMethod.by(new $() {}).invoke(a, i,b);
    }
    @Hook("android.app.Activity->startActivity")
    public static void Activity_startActivity2(Activity a, Intent i) {
        Log.d(TAG, "Activity_startActivity2 ");
        Intent intent = (Intent) i;
        Log.d(TAG ,"startActivity: "+intent);
        OriginalMethod.by(new $() {}).invoke(a, i);
    }
}
