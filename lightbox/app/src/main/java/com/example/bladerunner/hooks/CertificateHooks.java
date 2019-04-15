package com.example.bladerunner.hooks;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import com.example.bladerunner.Utils;

import java.io.FileInputStream;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 07/02/2017.
 */

public class CertificateHooks extends GenericHooks {

    @Hook("android.app.ApplicationPackageManager->getPackageInfo")
    public static PackageInfo ApplicationPackageManager_getPackageInfo(Object cw, String s, int i) {
        Log.d(TAG, "ApplicationPackageManager_getPackageInfo name= " + s);
        return OriginalMethod.by(new $() {}).invoke(cw,s, i);
    }
    @Hook("android.content.ContextWrapper->getPackageManager")
    public static PackageManager ContextWrapper_getPackageManager(Object cw) {
        Log.d(TAG, "ContextWrapper_getPackageManager " );
        PackageManager pm = OriginalMethod.by(new $() {}).invoke(cw);
            /*
            PackageInfo packageInfo = null;
            try {
                packageInfo = pm.getPackageInfo("org.sid.escapingtest",
                        PackageManager.GET_SIGNATURES);
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
            for (Signature signature : packageInfo.signatures) {
            // SHA1 the signature
            String sha1 = Utils.getSHA1(signature.toByteArray());
            // check is matches hardcoded value
            Log.d(Utils.TAG, "SIGNATURE: " + sha1);
            }
            Signature s = new Signature("w00t".getBytes());
            packageInfo.signatures[0] = s;
            */
        return pm;
    }
}
