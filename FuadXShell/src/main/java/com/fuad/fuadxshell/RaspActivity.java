package com.fuad.fuadxshell;

import android.app.AlertDialog;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

public class RaspActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String msg = getIntent().getStringExtra("message");

        super.onCreate(savedInstanceState);
        setContentView(android.R.style.Theme_Material_Light_Dialog_Alert);
        new AlertDialog.Builder(this)
                .setTitle("Error")
                .setMessage(msg != null ? msg : "Ha ocurrido un error desconocido")
                .setPositiveButton("Aceptar", (dialog, which) -> {
                    finishAffinity();
                })
                .setCancelable(false)
                .show();
    }
}
