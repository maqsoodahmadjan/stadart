package com.example.bladerunner;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.example.bladerunner.R;
import com.example.bladerunner.Utils;
import com.example.bladerunner.services.ActivityService;
import com.example.bladerunner.services.BenchmarkService;

import java.lang.reflect.Method;

import static com.example.bladerunner.NativeCode.stringFromJNI;

public class MainActivity extends Activity {
    SharedPreferences.Editor editor;
    SharedPreferences.Editor editor1;
    SharedPreferences.Editor editor2;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent act_service = new Intent(getApplicationContext(), ActivityService.class);
        startService(act_service);
        Log.d(Utils.TAG, "MyApp started main service");
        Log.d(Utils.TAG, "MainActivity called");
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        /*
        editor.putInt("app_running", 0);
        editor1.putInt("service_running", 0);
        editor2.putInt("service0_running", 0);
        editor.commit();
        editor1.commit();
        editor2.commit();
        super.onDestroy();
        */
    }
}
