package com.example.bladerunner.hooks;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Random;

/**
 * Created by vaioco on 07/12/2016.
 */

public class Seccon {
    private static final int LOGCAT_MAX_MSG_LENGTH = 3900;
    private final static boolean PRINT_SECCON_LOG = true;
    private final static String SECCON_MARKER = "!SECCON!:";

    public final static String JSON_OPERATION          = "operation";
    public final static String JSON_UID                = "uid";
    public final static String JSON_CLASS              = "class";
    public final static String JSON_METHOD             = "method";
    public final static String JSON_PROTO              = "proto";
    public final static String JSON_STACK              = "stack";
    public final static String JSON_DEX_SOURCE         = "source";
    public final static String JSON_DEX_OUTPUT         = "output";
    public final static String JSON_INVOKE_ARGS         = "args";

    public final static int OP_CLASS_NEW_INSTANCE = 1;
    public final static int OP_METHOD_INVOKE      = 2;
    public final static int OP_DEX_LOAD           = 3;

    public static String TAG = "seccon";

    /**
     * This method checks if an operation should be logged and logs
     * the message.
     *
     * @param msg JSON object which contains message
     *
     * @hide
     */
    public static void doSecconLog(int operation, JSONObject msg) {
        if (!PRINT_SECCON_LOG)
            return;

        int uid = android.system.Os.getuid();
        if (!uidIsLoggable(uid)) {
            return;
        }

        String output = makeOutput(operation, uid, msg);
        if (output != null) {
            printLogcat(output);
            //System.out.println(output);
        }
    }

    /**
     * @param output
     *
     * @hide
     */
    private static void printLogcat(String output) {
        if (output.length() > LOGCAT_MAX_MSG_LENGTH) {
            int id = (new Random()).nextInt(100);
            StringBuffer builder;
            for (int i = 0, j = 0; i < output.length(); i += LOGCAT_MAX_MSG_LENGTH, j++) {
                builder = new StringBuffer();
                if (i + LOGCAT_MAX_MSG_LENGTH < output.length()) {
                    builder.append(SECCON_MARKER)
                            .append("id")
                            .append(String.valueOf(id))
                            .append(":")
                            .append("p")
                            .append(String.valueOf(j))
                            .append(":")
                            .append(output.substring(i, i + LOGCAT_MAX_MSG_LENGTH));
                }
                else {
                    builder.append(SECCON_MARKER)
                            .append("id")
                            .append(String.valueOf(id))
                            .append(":")
                            .append("f")
                            .append(String.valueOf(j))
                            .append(":")
                            .append(output.substring(i, output.length()));
                }
                //System.out.println(builder.toString());
                Log.d(TAG,builder.toString() );
                builder = null;
            }
        }
        else
        {
            System.out.println(SECCON_MARKER + output);
        }
    }



    /**
     * The method creates string to output.
     *
     * @param operation the id of the operation
     * @param uid the uid of the application
     * @param msg message in JSON format
     *
     * @return string to output
     *
     * @hide
     */
    private static String makeOutput(int operation, int uid, JSONObject msg) {
        if (msg == null)
            return null;

        try {
            msg.put(Seccon.JSON_OPERATION, String.valueOf(operation));
            msg.put(Seccon.JSON_UID, String.valueOf(uid));
        }
        catch(JSONException e) {
            System.out.println("SECCON: Exception while putting values to JSON object!");
            return null;
        }

        return msg.toString();
    }



    /**
     * Checks if the operations of this uid should be logged.
     *
     * @param uid
     * @return <b>true</b> if should be logged, <b>false</b> - otherwise
     *
     * @hide
     */
    private static boolean uidIsLoggable(int uid) {
        if ((uid >= 10000) && (uid <= 99999)) { // uid is application uid
            return true;
        }

        return false;
    }

    /**
     * This method converts Stack Trace Element into string that can be put in
     * a log.
     *
     * @param ste Stack Trace Element
     * @return string that represents Stack Trace Element
     *
     * @hide
     */
    public static String convertSteToString(StackTraceElement ste) {
        if (ste == null) {
            return "null, null, null";
        }

        String stackEl = convertClassNameToDescriptor(ste.getClassName()) + ", "
                + ste.getMethodName() + ", "
                + "NULLPROTO";/*ste.getPrototype();*/
        return stackEl;
    }

    /**
     * @param className
     * @return
     *
     * @hide
     */
    public static String convertClassNameToDescriptor(String className) {
        if (className == null) {
            return null;
        }
        String str = "L" + className + ";";
        str = str.replace(".", "/");

        return str;
    }

    /**
     * This method converts method signature to prototype.
     *
     * @param signature
     * @return
     *
     * @hide
     */
    public static String convertSignatureToProto(String signature) {
        if (signature == null) {
            return null;
        }

        String res = signature.replace(".", "/");
        return res;
    }
}
