package com.example.bladerunner.hooks;

import android.content.SharedPreferences;
import android.util.Log;

import javax.crypto.Cipher;

import de.larma.arthook.$;
import de.larma.arthook.Hook;
import de.larma.arthook.OriginalMethod;

/**
 * Created by vaioco on 21/03/2017.
 */

public class SharedPrefHooks extends GenericHooks {

    @Hook("android.app.SharedPreferencesImpl$EditorImpl->putString")
    public static SharedPreferences.Editor Editor_putString(SharedPreferences.Editor e, String key, String value) {
        Log.d(TAG, "Editor_putString key: "+key+" value: "+value);
        return OriginalMethod.by(new $() {}).invoke(e,key,value);
    }


}
