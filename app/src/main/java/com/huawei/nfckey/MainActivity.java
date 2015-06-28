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

import java.io.InputStream;
import java.io.OutputStream;


public class MainActivity extends ActionBarActivity {
    private static final String TAG = "NFCKey";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        copyFile("door.key");
        copyFile("door.crt");
        setContentView(R.layout.activity_main);

        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        toolbar.setTitle(R.string.app_name);

        // Android Studio + app:theme = angry for me at moment
        // just set the text white really quick
        toolbar.setTitleTextColor(Color.parseColor("#ffffff"));

        Button setNdef = (Button) findViewById(R.id.set_ndef_button);
        setNdef.setOnClickListener(new View.OnClickListener() {
                                       @Override
                                       public void onClick(View view) {

                                           //
                                           // Technically, if this is past our byte limit,
                                           // it will cause issues.
                                           //
                                           // TODO: add validation
                                           //
                                           TextView getNdefString = (TextView) findViewById(R.id.ndef_text);
                                           String test = getNdefString.getText().toString();

                                           /* Intent intent = new Intent(view.getContext(), myHostApduService.class);
                                           intent.putExtra("ndefMessage", test);
                                           startService(intent);*/
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
            Log.i("tag", "copyFile() " + filename);
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
