package com.example.bladerunner.services;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.IBinder;
import android.util.Log;

import com.example.bladerunner.Utils;

public class CommonService extends Service {
    SharedPreferences.Editor editor;

    public CommonService() {
    }

    @Override
    public void onCreate() {
        Log.d(Utils.TAG, "CommonService onCreate");
        SharedPreferences sharedPref = getApplicationContext().getSharedPreferences("service0_running", Context.MODE_PRIVATE);
        editor = sharedPref.edit();
        //int running = sharedPref.getInt("service0_running",0);
        int running = 0;
        if(running == 0) {
            //editor.putInt("service0_running", 1);
            //editor.commit();
            Utils.loadHooks();
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(Utils.TAG, "CommonService onStartCommand");
        return Service.START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        // TODO: Return the communication channel to the service.
        throw new UnsupportedOperationException("Not yet implemented");
    }
    @Override
    public void onDestroy() {
        Log.d(Utils.TAG, "CommonService onDestroy");
        //editor.putInt("service0_running", 0);
        //editor.commit();
    }

}
