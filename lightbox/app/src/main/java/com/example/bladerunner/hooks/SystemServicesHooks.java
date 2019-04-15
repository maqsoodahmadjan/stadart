package com.example.bladerunner.hooks;

import android.location.Location;
import android.location.LocationManager;
import android.util.Log;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by sid on 07/03/17.
 */

public class SystemServicesHooks extends GenericHooks {
    public static Location MyLastKnown(LocationManager thiz, String provider){
        Log.d(TAG, "requested last known location for : " + provider);
        return OriginalMethod.by(new $() {}).invoke(thiz, provider);
    }
    @Hook("android.content.ContextWrapper->getSystemService")
    public static <T> T MyGetSystemService(Object thiz, Class<T> serviceClass){
        Log.d(TAG, "requested system service : " + serviceClass.getCanonicalName());
        return OriginalMethod.by(new $() {}).invoke(thiz, serviceClass);
    }

}
