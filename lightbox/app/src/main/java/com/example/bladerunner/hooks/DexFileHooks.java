package com.example.bladerunner.hooks;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import dalvik.system.DexClassLoader;
import dalvik.system.DexFile;
import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 07/12/2016.
 */

public class DexFileHooks extends GenericHooks{
   /*
    * Open a DEX file.  The value returned is a magic VM cookie.  On
    * failure, an IOException is thrown.

    private static Object openDexFile(String sourceName, String outputName, int flags,
                                      ClassLoader loader, DexPathList.Element[] elements) throws IOException {
    private static native Object openDexFileNative(String sourceName, String outputName, int flags,
            ClassLoader loader, DexPathList.Element[] elements);
   D  Found method: private static java.lang.Object dalvik.system.DexFile.openDexFile(java.lang.String,java.lang.String,int,java.lang.ClassLoader,dalvik.system.DexPathList$Element[])
         throws java.io.IOException
     D  Found method: private static native java.lang.Object dalvik.system.DexFile.openDexFileNative(java.lang.String,java.lang.String,int,java.lang.ClassLoader,dalvik.system.DexPathLi
        st$Element[])

    @Hook("dalvik.system.DexFile->openDexFile")
    public static Object DexFile_open (String sourceName, String outputName, int flags,
                                       ClassLoader loader, Object[] elements) throws IOException {
        Log.d(TAG, "DexFile_open called with source: " + sourceName + " output: " + outputName);
        JSONObject jsonObj = new JSONObject();
        StackTraceElement ste[] = java.lang.Thread.currentThread().getStackTrace();
        JSONArray jsArr = new JSONArray();
        for (int i = 0; i < ste.length; i++) {
            Log.d(TAG,"stack elem: " + ste[i].toString());
            jsArr.put(Seccon.convertSteToString(ste[i]));
        }
        try {
            jsonObj.put(Seccon.JSON_DEX_SOURCE, sourceName);
            jsonObj.put(Seccon.JSON_DEX_OUTPUT, outputName);
            jsonObj.put(Seccon.JSON_STACK, jsArr);
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Seccon.doSecconLog(Seccon.OP_DEX_LOAD, jsonObj);
        return OriginalMethod.by(new $() {}).invokeStatic(sourceName, outputName, flags, loader, elements);
    }
    */

    //DexClassLoader(String dexPath, String optimizedDirectory, String librarySearchPath, ClassLoader parent)
    @Hook("dalvik.system.DexClassLoader-><init>")
    public static void DexClassLoader_init(DexClassLoader thiz,String dexPath, String optimizedDirectory,
                                           String librarySearchPath, ClassLoader parent) {
        Log.d(TAG, "DexClassLoader_init");

        JSONObject jsonObj = new JSONObject();
        StackTraceElement ste[] = java.lang.Thread.currentThread().getStackTrace();
        JSONArray jsArr = new JSONArray();
        for (int i = 0; i < ste.length; i++) {
            jsArr.put(Seccon.convertSteToString(ste[i]));
        }
        try {
            jsonObj.put(Seccon.JSON_DEX_SOURCE, dexPath);
            jsonObj.put(Seccon.JSON_DEX_OUTPUT, optimizedDirectory); //constructor is equal to "<init>"
            jsonObj.put(Seccon.JSON_STACK, jsArr);
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Seccon.doSecconLog(Seccon.OP_DEX_LOAD, jsonObj);
        OriginalMethod.by(new $() {}).invoke(thiz, dexPath, optimizedDirectory,
                librarySearchPath, parent);
    }

}
