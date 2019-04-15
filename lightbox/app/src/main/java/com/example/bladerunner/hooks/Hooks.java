package com.example.bladerunner.hooks;

import android.app.Activity;
import android.hardware.Camera;
import android.net.ConnectivityManager;
import android.net.sip.SipAudioCall;
import android.telephony.TelephonyManager;
import android.util.Log;

import java.lang.reflect.Array;
import java.lang.reflect.Method;

import de.larma.arthook.$;
import de.larma.arthook.BackupIdentifier;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

import static de.larma.arthook.DebugHelper.logd;

/**
 * Created by vaioco on 24/11/2016.
 */

public class Hooks extends GenericHooks {
    /*
    @Hook("android.telephony.TelephonyManager->getDeviceId")
    public static String fix_getDeviceId(TelephonyManager tm){
        Log.d(TAG, "fixed getdeviceid");
        return "w00t" + OriginalMethod.by(new $() {}).invoke(tm);
    }
    @Hook("android.net.sip.SipAudioCall->startAudio")
    public static void SipAudioCall_startAudio(SipAudioCall call) {
        Log.d(TAG, "SipAudioCall_startAudio");
        OriginalMethod.by(new $() {}).invoke(call);
    }
    @Hook("android.app.Activity-><init>")
    public static void Activity_init(Activity a) {
        Log.d(TAG, "Activity_init");
        OriginalMethod.by(new $() {}).invoke(a);
    }

    /**
     * Sample hook of a static method

    @Hook("android.hardware.Camera->open")
    public static Camera Camera_open() {
        try {
            return OriginalMethod.by(new $() {}).invokeStatic();
        } catch (Exception e) {
            throw new SecurityException("We do not allow Camera access", e);
        }
    }*/
    /**
     * Sample hook of a static native method

    @Hook("java.lang.System->currentTimeMillis")
    public static long System_currentTimeMillis() {
        Log.d(TAG, "currentTimeMillis is much better in seconds :)");
        return (long) OriginalMethod.by(new $() {}).invokeStatic() / 1000L;
    }*/
    /**
     * Hooking an empty method

    @Hook("android.net.ConnectivityManager->setNetworkPreference")
    public static void ConnectivityManager_setNetworkPreference(ConnectivityManager manager, int preference) {
        Log.d(TAG, "Making something from nothing!");
        OriginalMethod.by(new $() {}).invoke(manager, preference);
    }*/

    /**
     * Sample hook of a member method used internally by the system
     * <p/>
     * Note how we use the BackupIdentifier here, because using reflection APIs to access
     * reflection APIs will cause loops...

    @Hook("java.lang.Class->getDeclaredMethod")
    @BackupIdentifier("Class_getDeclaredMethod")
    public static Method Class_getDeclaredMethod(Class cls, String name, Class[] params) {
        Log.d(TAG, "!!! getDeclaredMethod: " + cls + " -> " + name);
        Class<?>[] _params = null;
        if(name.equals("openDexFile")){
            try {
                _params = new Class<?>[params.length];
                System.arraycopy(params, 0, _params, 0, params.length);
                Class dexfile = Class.forName("dalvik.system.DexPathList$Element");
                Object array = Array.newInstance(dexfile, 1);
                params[params.length-1] = array.getClass();
                for(Class<?> x : params)
                    logd("getDeclaredMethod param: " + x.getName());
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
        return OriginalMethod.by("Class_getDeclaredMethod").invoke(cls, name, params);
    }
    */


}
