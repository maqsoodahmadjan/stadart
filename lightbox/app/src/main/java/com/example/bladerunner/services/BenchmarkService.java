package com.example.bladerunner.services;

import android.app.IntentService;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import com.example.bladerunner.Utils;

public class BenchmarkService extends IntentService {

    public BenchmarkService(String name) {
        super(name);
    }
    public BenchmarkService() {
        super("");
    }
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(Utils.TAG, "BenchmarkService started");
        return START_STICKY;
    }
    @Override
    protected void onHandleIntent(Intent intent) {
        Log.d(Utils.TAG, "BenchmarkService started");
    }
}
