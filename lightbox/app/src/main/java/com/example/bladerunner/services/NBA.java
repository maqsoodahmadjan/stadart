package com.example.bladerunner.services;

import android.app.IntentService;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import com.example.bladerunner.Utils;

public class NBA extends IntentService {

    public NBA() {
        super("");
    }

    public NBA(String name) {
        super(name);
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        Log.d(Utils.TAG, "NBA started");

    }
}
