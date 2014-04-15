package com.keysofpeace.app.ui;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.keysofpeace.app.R;

public class LoginActivity extends Activity {
	private static final int VISIBLE = 0;
	private static final int INVISIBLE = 4;
	private static final Integer STATUS_OK = 0;
	private static final Integer STATUS_ERROR = -1;
	private ProgressBar checkBar;
	private EditText email;
	private EditText password;
	private TextView errorText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        errorText = (TextView)findViewById(R.id.login_error_txt);
        email = (EditText)findViewById(R.id.email);
        password = (EditText)findViewById(R.id.password);
        final Button button = (Button) findViewById(R.id.login);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
            	String emailValue = email.getText().toString();
            	String passwordValue = password.getText().toString();
            	errorText.setVisibility(INVISIBLE);
                new CheckEmailPasswordTask().execute(emailValue,passwordValue);
            }
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.login, menu);
        return true;
    }
    public class CheckEmailPasswordTask extends AsyncTask<String, Void, Integer> {
    	String memail = "qwerty";
    	String mpassword = "qwe123";
    	
    	@Override
		protected void onPreExecute() {
			super.onPreExecute();
			checkBar = (ProgressBar) findViewById(R.id.checkbar);
    		checkBar.setVisibility(VISIBLE);
		}

    	@Override
    	protected Integer doInBackground(String... params) {
    		if (params[0].equals(memail) && params[1].equals(mpassword)) return STATUS_OK;
    		else return STATUS_ERROR;
    	}
    	
    	@Override
    	protected void onPostExecute(Integer result) {
    		super.onPostExecute(result);
    		checkBar.setVisibility(INVISIBLE);
    		if (result==STATUS_OK) {
    			//открыть новый activity
    			Toast.makeText(LoginActivity.this, "OK", Toast.LENGTH_LONG).show();
    		}
    		else {
    			checkBar.setVisibility(INVISIBLE);
    			password.setText("");
    			errorText.setVisibility(VISIBLE);
    			Toast.makeText(LoginActivity.this, "Invalid email/password field", Toast.LENGTH_LONG).show();
    		}
    	}
    }
}
