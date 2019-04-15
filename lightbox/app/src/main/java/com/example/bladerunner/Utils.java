package com.example.bladerunner;

import android.util.Log;

import com.example.bladerunner.hooks.CertificateHooks;
import com.example.bladerunner.hooks.ClassHooks;
import com.example.bladerunner.hooks.CryptoHooks;
import com.example.bladerunner.hooks.CursorHooks;
import com.example.bladerunner.hooks.DexFileHooks;
import com.example.bladerunner.hooks.FSHooks;
import com.example.bladerunner.hooks.Hooks;
import com.example.bladerunner.hooks.HttpHooks;
import com.example.bladerunner.hooks.HttpsHooks;
import com.example.bladerunner.hooks.IPCHooks;
import com.example.bladerunner.hooks.NetworkHooks;
import com.example.bladerunner.hooks.RuntimeHooks;
import com.example.bladerunner.hooks.SMSHooks;
import com.example.bladerunner.hooks.Seccon;
import com.example.bladerunner.hooks.SharedPrefHooks;
import com.example.bladerunner.hooks.SystemServicesHooks;
import com.example.bladerunner.hooks.WebviewHooks;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import de.larma.arthook.ArtHook;

/**
 * Created by vaioco on 01/11/2016.
 */

public class Utils {

    public static String TAG = "blade";
    public static final String BOBS_PACKAGE = "PCK_TROVAMI";
    //public static final String BOBS_PACKAGE = "org.sid.escapingtest";
    //static final String BOBS_PACKAGE = "com.quicinc.vellamo";
    public static final String BOBS_MAIN_ACTIVITY = "ACTIVITY_TROVAMI";
    //public static final String BOBS_MAIN_ACTIVITY = "org.sid.escapingtest.MainActivity";
    //public static final String BOBS_MAIN_ACTIVITY = "com.unity3d.player.UnityPlayerActivity";
    //static final String BOBS_MAIN_ACTIVITY = "com.quicinc.vellamo.main.MainActivity";


    public static void loadHooks()
    {
        /*
        ArtHook.hook(HttpsHooks.class);
        ArtHook.hook(IPCHooks.class);
        ArtHook.hook(CryptoHooks.class);
        ArtHook.hook(RuntimeHooks.class);
        ArtHook.hook(SMSHooks.class);
        ArtHook.hook(WebviewHooks.class);
        ArtHook.hook(Hooks.class);
        ArtHook.hook(CertificateHooks.class);
        */
        ArtHook.hook(NetworkHooks.class);
        ArtHook.hook(SharedPrefHooks.class);
        ArtHook.hook(SystemServicesHooks.class);
        ArtHook.hook(DexFileHooks.class);
        ArtHook.hook(FSHooks.class);
        ArtHook.hook(CursorHooks.class);
        ArtHook.hook(HttpHooks.class);
    }
    public static void printMap(String target, boolean flag){

        String mapsLocation = "/proc/self/maps";
        try {
            BufferedReader br = new BufferedReader(new FileReader(mapsLocation));

            for(String line; (line = br.readLine()) != null; ) {
                /*&& line.contains("x")) { */
                if (line.contains(target) || flag){
                    Log.d(TAG, line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void printStackTrace()
    {
        Log.d(Utils.TAG, "stacktrace: ", new Exception());
    }
    public static void newInstance_helper(Class thiz){
        JSONObject jsonObj = new JSONObject();
        StackTraceElement ste[] = java.lang.Thread.currentThread().getStackTrace();
        JSONArray jsArr = new JSONArray();
        for (int i = 0; i < ste.length; i++) {
            jsArr.put(Seccon.convertSteToString(ste[i]));
        }
        try {
            jsonObj.put(Seccon.JSON_CLASS, Seccon.convertClassNameToDescriptor(thiz.getName()));
            jsonObj.put(Seccon.JSON_METHOD, "<init>"); //constructor is equal to "<init>"
            jsonObj.put(Seccon.JSON_PROTO, "()V"); //default signature
            jsonObj.put(Seccon.JSON_STACK, jsArr);
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Seccon.doSecconLog(Seccon.OP_CLASS_NEW_INSTANCE, jsonObj);
        //end SECCON
    }
    private static String getSignature(Object... args) {
        StringBuilder result = new StringBuilder();

        result.append('(');
        for (int i = 0; i < args.length; i++) {
            result.append(getSignature(args[i]));
        }
        result.append(")V");
        return result.toString();
    }
    public static void invoke_helper(Method m, Object receiver, Object... args) {
        JSONObject jsonObj = new JSONObject();
        StackTraceElement ste[] = java.lang.Thread.currentThread().getStackTrace();
        JSONArray jsArr = new JSONArray();
        JSONArray jsArgs = new JSONArray();
        if (args != null) {
            for (int k = 0; k < args.length; k++) {
                if (args[k] != null)
                    jsArgs.put(args[k].toString());
            }
        }
        for (int i = 0; i < ste.length; i++) {
            jsArr.put(Seccon.convertSteToString(ste[i]));
        }
        try {
            jsonObj.put(Seccon.JSON_CLASS, Seccon.convertClassNameToDescriptor(m.getDeclaringClass().getName()));
            jsonObj.put(Seccon.JSON_METHOD, m.getName());
            jsonObj.put(Seccon.JSON_PROTO, "NULLPROTO");
            jsonObj.put(Seccon.JSON_STACK, jsArr);
            jsonObj.put(Seccon.JSON_INVOKE_ARGS, jsArgs);
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Seccon.doSecconLog(Seccon.OP_METHOD_INVOKE, jsonObj);
    }
    public static String getSHA1(byte[] sig) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA1", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        digest.update(sig);
        byte[] hashtext = digest.digest();
        return bytesToHex(hashtext);
    }
    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
