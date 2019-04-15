package com.example.bladerunner;

import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.util.Log;

import com.example.bladerunner.services.ActivityService;
import com.example.bladerunner.services.BenchmarkService;
import com.example.bladerunner.services.CommonService;
import com.example.bladerunner.services.NBA;

import java.lang.reflect.Method;

/* ARTDroid + ARTHook */


/**
 * Created by vaioco on 01/11/2016.
 */

public class MyApp extends Application {
    SharedPreferences.Editor editor;
    static {
        //System.loadLibrary("vhooks");
    }
    public MyApp() {
        super();
    }
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(Utils.TAG, "MyApp called ***can");

        Intent act_service = new Intent(getApplicationContext(), ActivityService.class);
        startService(act_service);
        Log.d(Utils.TAG, "MyApp started main service");


    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
    }
}
/*
            try {
                Log.d(Utils.TAG, "MyApp called ***running  = " );
                Context c = getApplicationContext().createPackageContext(Utils.BOBS_PACKAGE,
                        Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY);
                ApplicationInfo appinfo = c.getApplicationInfo();
                Log.d(Utils.TAG, "caricata app: " + c.getPackageName());
                Log.d(Utils.TAG, "app info: " + appinfo);
                int id = android.os.Process.myPid();
                Log.d(Utils.TAG, "master PID: " + id);
                ClassLoader cl = c.getClassLoader();
                Thread.currentThread().setContextClassLoader(cl);
                Intent intent = new Intent();
                int flags = Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_REORDER_TO_FRONT | Intent.FLAG_ACTIVITY_NO_HISTORY;
                intent.setComponent(new ComponentName(Utils.BOBS_PACKAGE, Utils.BOBS_MAIN_ACTIVITY));
                intent.setFlags(flags);
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
 */