package com.example.bladerunner;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.example.bladerunner.services.ActivityService;

public class MyReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        // TODO: This method is called when the BroadcastReceiver is receiving
        // an Intent broadcast.
        Intent act_service = new Intent(context, ActivityService.class);
        context.startService(act_service);
        Log.d(Utils.TAG, "MyApp started main service");    }
}
