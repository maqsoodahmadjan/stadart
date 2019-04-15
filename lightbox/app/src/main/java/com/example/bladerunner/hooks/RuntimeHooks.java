package com.example.bladerunner.hooks;

import android.app.PendingIntent;
import android.telephony.SmsManager;
import android.util.Log;

import java.io.File;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class RuntimeHooks extends GenericHooks {

    @Hook("java.lang.Runtime->exec")
    public static Process Runtime_exec(Runtime r, String[] s1,String[] s2,File f) {
        Log.d(TAG, "Runtime_exec string: " + s1 + " s2: " + s2);
        return OriginalMethod.by(new $() {}).invoke(r,s1,s2,f);
    }
}
