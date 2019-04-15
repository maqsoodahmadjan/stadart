package com.example.bladerunner;

import android.os.Build;

/**
 * Created by vaioco on 07/02/2017.
 */

public class Common {
    // checks
    public static final int SDK = Build.VERSION.SDK_INT;
    public static final boolean JB_NEWER = SDK >= Build.VERSION_CODES.JELLY_BEAN;
    public static final boolean JB_MR1_NEWER = SDK >= Build.VERSION_CODES.JELLY_BEAN_MR1;
    public static final boolean JB_MR2_NEWER = SDK >= Build.VERSION_CODES.JELLY_BEAN_MR2;
    public static final boolean KITKAT_NEWER = SDK >= Build.VERSION_CODES.KITKAT;
    public static final boolean LOLLIPOP_NEWER = SDK >= Build.VERSION_CODES.LOLLIPOP;
    public static final boolean LOLLIPOP_MR1_NEWER = SDK >= Build.VERSION_CODES.LOLLIPOP_MR1;
    public static final boolean MARSHMALLOW_NEWER = SDK >= Build.VERSION_CODES.M; // MARSHMALLOW

    // classes
    public static final String PACKAGEMANAGERSERVICE = "com.android.server.pm.PackageManagerService";
    public static final String DEVICEPOLICYMANAGERSERVICE = (LOLLIPOP_NEWER) ? "com.android.server.devicepolicy.DevicePolicyManagerService"
            : "com.android.server.DevicePolicyManagerService";
    public static final String INSTALLEDAPPDETAILS = "com.android.settings.applications.InstalledAppDetails";
    public static final String PACKAGEINSTALLERACTIVITY = "com.android.packageinstaller.PackageInstallerActivity";
    public static final String INSTALLAPPPROGRESS = "com.android.packageinstaller.InstallAppProgress";
    public static final String CANBEONSDCARDCHECKER = "com.android.settings.applications.CanBeOnSdCardChecker";
    public static final String UNINSTALLERACTIVITY = "com.android.packageinstaller.UninstallerActivity";
    public static final String UNINSTALLAPPPROGRESS = "com.android.packageinstaller.UninstallAppProgress";
    public static final String FDROIDAPPDETAILS = "org.fdroid.fdroid.AppDetails";
    public static final String PACKAGEPARSER = "android.content.pm.PackageParser";
    public static final String JARVERIFIER = "java.util.jar.JarVerifier$VerifierEntry";
    public static final String SIGNATURE = "java.security.Signature";
    public static final String BACKUPRESTORECONFIRMATION = "com.android.backupconfirm.BackupRestoreConfirmation";
    public static final String PACKAGEMANAGERREPOSITORY = "com.google.android.finsky.appstate.PackageManagerRepository";
    public static final String UTILS = "com.android.settings.Utils";
    public static final String APPOPSDETAILS = "com.android.settings.applications.AppOpsDetails";
    public static final String SELFUPDATESCHEDULER = "com.google.android.finsky.utils.SelfUpdateScheduler";
    public static final String APPOPSXPOSED_APPOPSACTIVITY = "at.jclehner.appopsxposed.AppOpsActivity";
    public static final String APPERRORDIALOG = "com.android.server.am.AppErrorDialog";
}
