package com.example.bladerunner.services;

import android.app.ActivityManager;
import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.example.bladerunner.MainActivity;
import com.example.bladerunner.Utils;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class ActivityService extends Service {
    SharedPreferences.Editor editor;
    private static final String IActivityManagerClassName = "android.app.IActivityManager";
    private static final String IAMStubClassName = IActivityManagerClassName + ".Stub";
    private static final String IAMStubProxyClassName = IAMStubClassName + ".Proxy";
    private static final String ILocationManagerClassName = "android.location.ILocationManager";
    private static final String ILMStubClassName = ILocationManagerClassName + ".Stub";
    private static final String ILMStubProxyClassName = ILMStubClassName + ".Proxy";
    private static final String IAppThreadClassName = "android.app.ApplicationThreadNative";
    private static final String IATStubClassName = IAppThreadClassName + ".Stub";
    private static final String IATStubProxyClassName = IATStubClassName + ".Proxy";
    private static final String IAppThreadProxyClassName = "android.app.ApplicationThreadProxy";


    private IActivityService.Stub mBinder  = new IActivityService.Stub(){

        @Override
        public int start() throws RemoteException {
            return 0;
        }

        @Override
        public int stop() throws RemoteException {
            return 0;
        }
    };
    public ActivityService() {
    }

    @Override
    public void onCreate() {
        Log.d(Utils.TAG, "ActivityService onCreate");
        SharedPreferences sharedPref = getApplicationContext().getSharedPreferences("service_running",Context.MODE_PRIVATE);
        editor = sharedPref.edit();
        int running = sharedPref.getInt("service_running",0);
        running = 0;
        if(running == 0) {
            editor.putInt("service_running", 1);
            editor.commit();
            Utils.loadHooks();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(Utils.TAG, "ActivityService onStartCommand");
        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, notificationIntent, 0);
        Notification notification = new Notification.Builder(this)
                .setContentTitle("title")
                .setContentText("mess")
                .setContentIntent(pendingIntent)
                .setTicker("pd")
                .build();
        startForeground(101, notification);
        return Service.START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        // TODO: Return the communication channel to the service.
        return mBinder;
    }
    @Override
    public void onDestroy() {
        Log.d(Utils.TAG, "ActivityService onDestroy");
        //editor.putInt("service_running", 0);
        //editor.commit();
    }

}

/*
            try {
                Class clILocationManager = Class.forName(IAppThreadClassName);
                Class[] lmSubClasses = clILocationManager.getDeclaredClasses();
                Method[] lmMethods = clILocationManager.getDeclaredMethods();
                Log.d(Utils.TAG, String.format("Found %d inner classes in %s", lmSubClasses.length, IAppThreadClassName));
                Log.d(Utils.TAG, String.format("Found %d methods in %s", lmMethods.length, IAppThreadClassName));
                Class clLMStub = null;
                for (Class c : lmSubClasses) {
                    Log.d(Utils.TAG, String.format("Inner class: %s", c.getCanonicalName()));
                    if (c.getCanonicalName().equals(IATStubProxyClassName)) {
                        clLMStub = c;
                        break;
                    }
                }
                Method asInterface = null;
                for(Method m : lmMethods){
                    Log.d(Utils.TAG, String.format("Method: %s", m.getName()));
                    if(m.getName().equals("asInterface")){
                        asInterface = m;
                        break;
                    }
                }
      *//*
Class clAppThreadProxy = Class.forName(IAppThreadProxyClassName);
    ActivityManager am = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
    Class ClIAppThread = (Class) asInterface.invoke(null,b);
Log.d(Utils.TAG, "MyApp called ***running  = " + running);
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
        //Utils.loadHooks();
        //c.startActivity(intent);
        } catch (PackageManager.NameNotFoundException e) {
        e.printStackTrace();
        } catch (ClassNotFoundException e) {
        e.printStackTrace();
        } catch (InvocationTargetException e) {
        e.printStackTrace();
        } catch (IllegalAccessException e) {
        e.printStackTrace();
        }
 */