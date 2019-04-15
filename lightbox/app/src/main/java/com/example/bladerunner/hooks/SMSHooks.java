package com.example.bladerunner.hooks;

import android.app.PendingIntent;
import android.telephony.SmsManager;
import android.util.Log;
import android.webkit.WebView;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class SMSHooks extends GenericHooks {

    @Hook("android.telephony.SmsManager->sendTextMessage")
    public static void SmsManager_sendTextMessage(SmsManager sms, String s1, String s2, String s3 , PendingIntent i1, PendingIntent i2) {
        Log.d(TAG, "SmsManager_sendTextMessage num: " + s1);
        OriginalMethod.by(new $() {}).invoke(sms,s1,s2,s3,i1,i2);
    }
}
