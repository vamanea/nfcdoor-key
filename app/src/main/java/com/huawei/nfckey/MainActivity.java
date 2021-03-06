package com.huawei.nfckey;

import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.graphics.Color;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;


public class MainActivity extends ActionBarActivity {
    private static final String TAG = "NFCKey";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        System.loadLibrary("app");


        copyFile("door.key");
        copyFile("door.crt");
        copyFile("ecc.key");
        copyFile("cert.pem");

        try {
            utils.generateSessionCert(getBaseContext());
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate ECC key:" + e.getMessage());
        }

        setContentView(R.layout.activity_main);

        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        toolbar.setTitle(R.string.app_name);

        TextView rootHash = (TextView)findViewById(R.id.root_hash);
        TextView sessionHash = (TextView)findViewById(R.id.session_hash);
        try {
            rootHash.setText(utils.certThumbprint(getBaseContext()));
        }catch (Exception e) {
            rootHash.setText("no key");
        }

        try {
            sessionHash.setText(utils.sessionThumbprint(getBaseContext()));
        }catch (Exception e) {
            sessionHash.setText("no key");
        }

        // Android Studio + app:theme = angry for me at moment
        // just set the text white really quick
        toolbar.setTitleTextColor(Color.parseColor("#ffffff"));

        Button setNdef = (Button) findViewById(R.id.set_ndef_button);
        setNdef.setOnClickListener(new View.OnClickListener() {
                                       @Override
                                       public void onClick(View view) {
                                           TextView sessionHash = (TextView)findViewById(R.id.session_hash);

                                           try {
                                               utils.generateSessionCert(getApplicationContext());
                                               sessionHash.setText(utils.sessionThumbprint(getBaseContext()));
                                           }catch (Exception e) {
                                               sessionHash.setText("no key");
                                           }
                                       }
                                   }
        );
    }

    private void copyFile(String filename) {
        AssetManager assetManager = this.getAssets();

        InputStream in = null;
        OutputStream out = null;
        String newFileName = null;
        try {
            Log.i(TAG, "copyFile() " + filename);
            in = assetManager.open(filename);
            out = getBaseContext().openFileOutput(filename, Context.MODE_PRIVATE);

            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
            in = null;
            out.flush();
            out.close();
            out = null;
        } catch (Exception e) {
            Log.e(TAG, "Exception in copyFile() "+e.toString());
        }

    }
}
