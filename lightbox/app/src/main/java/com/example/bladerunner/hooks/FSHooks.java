package com.example.bladerunner.hooks;

import android.app.Activity;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URI;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 24/11/2016.
 */

public class FSHooks extends GenericHooks{
    /*
    @Hook("android.content.ContextWrapper->openFileInput")
    public static void ContextWrapper_openFileOutput(ContextWrapper cw, String s , int i) {
        Log.d(TAG, "ContextWrapper_openFileOutput name= " + s + " mode: " + i);
        OriginalMethod.by(new $() {}).invoke(cw,s,i);
    }
    @Hook("android.content.ContextWrapper->openFileInput")
    public static void ContextWrapper_openFileOutput(ContextWrapper cw, String s ) {
        Log.d(TAG, "ContextWrapper_openFileOutput name= " + s );
        OriginalMethod.by(new $() {}).invoke(cw,s);
    }*/
    @Hook("android.app.ContextImpl->openFileInput")
    public static FileInputStream ContextWrapperImpl_openFileInput(Object cw, String s) {
        Log.d(TAG, "ContextWrapperImpl_openFileInput name= " + s);
        return OriginalMethod.by(new $() {}).invoke(cw,s);
    }
    @Hook("android.app.ContextImpl->openFileOutput")
    public static FileOutputStream ContextWrapperImpl_openFileOutput(Object cw, String s, int mode ) {
        Log.d(TAG, "ContextWrapper_openFileOutput name= " + s );
        return OriginalMethod.by(new $() {}).invoke(cw,s, mode);
    }
    @Hook("java.io.File-><init>")
    public static void MyFile(File thiz, String path){
        Log.d(TAG, "creating new file: " + path);
         OriginalMethod.by(new $() {}).invoke(thiz, path);

    }
}
