package com.example.bladerunner.hooks;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.InvocationTargetException;

import de.larma.arthook.$;
import de.larma.arthook.BackupIdentifier;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 07/12/2016.
 */

public class ClassHooks extends GenericHooks {
    //public native T newInstance() throws InstantiationException, IllegalAccessException;
    /*
    @Hook("java.lang.Class->newInstance")
    @BackupIdentifier("org.sid.hooks.newinstance")
    public static <T> T Class_new() throws InstantiationException, IllegalAccessException{
        Log.d(TAG, "Class_new :  clsname is ");
        /*
        JSONObject jsonObj = new JSONObject();
        StackTraceElement ste[] = java.lang.Thread.currentThread().getStackTrace();
        JSONArray jsArr = new JSONArray();
        for (int i = 0; i < ste.length; i++) {
            jsArr.put(Seccon.convertSteToString(ste[i]));
        }
        try {
            jsonObj.put(Seccon.JSON_CLASS, Seccon.convertClassNameToDescriptor(thiz.getClass().getName()));
            jsonObj.put(Seccon.JSON_METHOD, "<init>"); //constructor is equal to "<init>"
            jsonObj.put(Seccon.JSON_PROTO, "()V"); //default signature
            jsonObj.put(Seccon.JSON_STACK, jsArr);
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Seccon.doSecconLog(Seccon.OP_CLASS_NEW_INSTANCE, jsonObj);
        //end SECCON

        return OriginalMethod.by("org.sid.hooks.newinstance").invokeStatic(null);
    } */
    private static String getSignature(Object... args) {
        StringBuilder result = new StringBuilder();

        result.append('(');
        for (int i = 0; i < args.length; i++) {
            result.append(getSignature(args[i]));
        }
        result.append(")V");

        return result.toString();
    }
    /*
    @Hook("java.lang.reflect.Constructor->newInstance")
    @BackupIdentifier("org.sid.hooks.newinstance")
    public static <T> T Constructor_new(Object thiz, Object... args) throws InstantiationException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Log.d(TAG, "Constructor_new on " + thiz.getClass().getCanonicalName());
        //begin SECCON
        JSONObject jsonObj = new JSONObject();
        StackTraceElement ste[] = java.lang.Thread.currentThread().getStackTrace();
        JSONArray jsArr = new JSONArray();
        for (int i = 0; i < ste.length; i++) {
            jsArr.put(Seccon.convertSteToString(ste[i]));
        }
        try {
            jsonObj.put(Seccon.JSON_CLASS, Seccon.convertClassNameToDescriptor(thiz.getClass().getName()));
            jsonObj.put(Seccon.JSON_METHOD, "<init>"); //constructor is equal to "<init>"
            jsonObj.put(Seccon.JSON_PROTO, Seccon.convertSignatureToProto(getSignature(args)));
            jsonObj.put(Seccon.JSON_STACK, jsArr);
        } catch (JSONException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Seccon.doSecconLog(Seccon.OP_CLASS_NEW_INSTANCE, jsonObj);
        //end SECCON
        return OriginalMethod.by("org.sid.hooks.newinstance").invokeStatic(thiz,args);
    } */

}
