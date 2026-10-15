package com.fuad.fuadx.errormsgbox;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Color;
import android.os.Process;
import android.util.Log;
import android.view.Gravity;
import android.widget.TextView;

import java.util.concurrent.CountDownLatch;

public class ErrorMsgBox {
    private static final String TAG = "ErrorMsgBox";

    protected ErrorMsgBox() {
        /* Empty intentionally */
    }

    public static synchronized void displayErrorMsgBox(Context ctx, ErrorCodes title,
                                                       ErrorCodes msg) {
        try {
            AlertDialog.Builder builder = new AlertDialog.Builder(ctx);
            CountDownLatch latch = new CountDownLatch(1);
            builder.setTitle(title.getValueStr());
            builder.setIcon(android.R.drawable.ic_dialog_alert);
            TextView textView = new TextView(ctx);
            textView.setTextSize(16);
            textView.setText(msg.getValueStr());
            textView.setGravity(Gravity.CENTER);
            textView.setTextColor(Color.BLACK);
            builder.setView(textView);
            builder.setPositiveButton("Aceptar", (dialog, which) -> {
                latch.countDown();
                ((Activity) ctx).finishAndRemoveTask();
                Process.killProcess(Process.myPid());
            });
            builder.setCancelable(false);
            ((Activity) ctx).runOnUiThread(() -> builder.create().show());
        }
        catch (Exception e) {
            Log.e(TAG, "Failed while either building or running on UI Thread. Shutting down");
            throw e;
        }
    }
}
