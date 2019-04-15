package com.example.bladerunner.hooks;

import android.content.ContextWrapper;
import android.util.Log;

import javax.crypto.Cipher;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class CryptoHooks extends GenericHooks {
    @Hook("javax.crypto.Cipher->doFinal")
    public static byte[] Cipher_doFinal(Cipher c, byte[] b) {
        Log.d(TAG, "Cipher_doFinal ");
        return OriginalMethod.by(new $() {}).invoke(c,b);
    }

    @Hook("javax.crypto.Cipher->getInstance")
    public static Cipher Cipher_getInstance(String s) {
        Log.d(TAG, "Cipher_getInstance ");
        return OriginalMethod.by(new $() {}).invokeStatic(s);
    }
}
