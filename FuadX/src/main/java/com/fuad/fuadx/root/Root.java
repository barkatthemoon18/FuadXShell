package com.fuad.fuadx.root;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import com.fuad.fuadx.reflection.Reflection;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Scanner;

public class Root {
    private static final String TAG = "RootLibrary";

    private static boolean checkPermissiveness() {
        try {
            Method isSelinuxEnabled = Reflection.getMethod("android.os.SELinux",
                    "isSELinuxEnabled");
            if (isSelinuxEnabled != null) {
                boolean isEnabled = (boolean) isSelinuxEnabled.invoke(null);
                boolean isEnforced = isSelinuxEnforced();
                Log.e(TAG, "SELinux enforced: " + (isEnabled && isEnforced));
                return isEnabled && isEnforced;
            }
            else {
                Log.e(TAG, "Failed to reflect");
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error checking SELinux: " + e.getMessage());
        }
        return false;
    }

    private static boolean isSelinuxEnforced() {
        try {
            Process process = Runtime.getRuntime().exec("getenforce");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process
                    .getInputStream()));
            String status = reader.readLine();
            Log.e(TAG, "getenforce status: " + status);
            return "Enforcing".equalsIgnoreCase(status) || status == null;
        }
        catch (IOException e) {
            Log.e(TAG, "Error executing getenforce: " + e.getMessage());
        }
        return false;
    }

    private static boolean checkRootPkgs(Context ctx) {
        try {
            List<PackageInfo> installedPkgs = ctx.getPackageManager()
                    .getInstalledPackages(PackageManager.GET_META_DATA);
            for (RootPkgs pkg : RootPkgs.values()) {
                for (PackageInfo pkgInfo : installedPkgs) {
                    if (pkgInfo.packageName.equals(pkg.getPkgName())) {
                        Log.e(TAG, "Root package found: " + pkg.getPkgName());
                        return true;
                    }
                }
                Log.e(TAG, "Not found root package: " + pkg.getPkgName());
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error while checking root packages: " + e.getMessage(), e);
        }
        return false;
    }

    private static boolean checkDangerousPkgs(Context ctx) {
        try {
            List<PackageInfo> installedPkgs = ctx.getPackageManager()
                    .getInstalledPackages(PackageManager.GET_META_DATA);
            for (DangerousPkgs pkg : DangerousPkgs.values()) {
                for (PackageInfo pkgInfo : installedPkgs) {
                    if (pkgInfo.packageName.equals(pkg.getPkgName())) {
                        Log.e(TAG, "Dangerous package found: " + pkg.getPkgName());
                        return true;
                    }
                }
                Log.e(TAG, "Not found dangerous package: " + pkg.getPkgName());
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error while checking dangerous packages: " + e.getMessage(), e);
        }
        return false;
    }

    private static boolean checkCloakingPkgs(Context ctx) {
        try {
            List<PackageInfo> installedPkgs = ctx.getPackageManager()
                    .getInstalledPackages(PackageManager.GET_META_DATA);
            for (CloakingPkgs pkg : CloakingPkgs.values()) {
                for (PackageInfo pkgInfo : installedPkgs) {
                    if (pkgInfo.packageName.equals(pkg.getPkgName())) {
                        Log.e(TAG, "Cloaking package found: " + pkg.getPkgName());
                        return true;
                    }
                }
                Log.e(TAG, "Not found cloaking package: " + pkg.getPkgName());
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error while checking cloaking packages: " + e.getMessage(), e);
        }
        return false;
    }

    private static boolean checkSuPaths() {
        try {
            for (SuPaths path : SuPaths.values()) {
                Log.e(TAG, "Testing: " + path.getPath());
                File dir = new File(path.getPath());
                Log.e(TAG, "Dir: " + dir.getPath() + ", exists: " + dir.exists() +
                        ", isDirectory: " + dir.isDirectory());
                if (dir.exists() && dir.isDirectory()) {
                    Log.e(TAG, "Exists: " + path.getPath());
                    String[] files = dir.list();
                    if (files != null) {
                        for (String file : files) {
                            Log.e(TAG, "File: " + file);
                            if (file.equals("su")) {
                                Log.e(TAG, "Found su binary in path: " + path.getPath());
                                return true;
                            }
                        }
                    }
                }
                else if (dir.exists()) {
                    Log.e(TAG, "Found su binary in path: " + path.getPath());
                    return true;
                }
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error while checking su paths: " + e.getMessage(), e);
        }
        return false;
    }

    private static boolean checkPathsNonRW() {
        String mountPoint;
        String mountOpts;
        String[] lines = mountReader();

        if (lines == null)
            return false;
        for (String line : lines) {
            String[] args = line.split(" ");
            if (args.length < 6) {
                Log.e(TAG, "Error while parsing: " + line);
                continue;
            }

            mountPoint = args[2];
            mountOpts = args[5];

            for (NonRwPaths path : NonRwPaths.values()) {
                Log.e(TAG, "Testing potential RW Path: " + path.getPath());
                if (mountPoint.equalsIgnoreCase(path.getPath())) {
                    mountOpts = mountOpts.replace("(","");
                    mountOpts = mountOpts.replace(")","");
                    for (String opt : mountOpts.split(",")) {
                        if (opt.equalsIgnoreCase("rw")) {
                            Log.e(TAG, "Found rw mount point: " + mountPoint);
                            return true;
                        }
                    }
                }
            }
        }
        Log.e(TAG, "Not found RW mount point");
        return false;
    }

    private static String[] mountReader() {
        try {
            InputStream inputStream = Runtime.getRuntime().exec("mount").getInputStream();
            if (inputStream == null)
                return null;
            String propVal = new Scanner(inputStream).useDelimiter("\\A").next();
            return propVal.split("\n");
        }
        catch (IOException e) {
            Log.e(TAG, "Error while reading mount: " + e.getMessage(), e);
            return null;
        }
    }

    public static String runProbe(Context ctx) {
        return Boolean.toString(Root.checkRootPkgs(ctx) ||
                Root.checkDangerousPkgs(ctx) ||
                Root.checkCloakingPkgs(ctx) ||
                Root.checkSuPaths() ||
                Root.checkPathsNonRW() ||
                Root.checkPermissiveness());
    }
}
