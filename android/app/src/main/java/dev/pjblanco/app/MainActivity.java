package dev.pjblanco.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.ViewGroup;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.TextView;

/**
 * A single-activity shell that shows the site in a WebView.
 *
 * <p>When {@code BuildConfig.SITE_URL} is empty the app serves the copy of the
 * site that the build bundled into {@code assets/www}; otherwise it points at
 * the live deployment. Either way navigation stays inside the app, the hardware
 * back button walks the WebView history, and non-http schemes (mailto:, tel:)
 * are handed to the matching system app.
 */
public class MainActivity extends Activity {

    private static final String OFFLINE_HOME = "file:///android_asset/www/index.html";

    private WebView webView;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        webView.setBackgroundColor(Color.WHITE);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setAllowContentAccess(true);
        settings.setSupportZoom(false);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);

        webView.setWebViewClient(new ShellWebViewClient());

        FrameLayout container = new FrameLayout(this);
        container.addView(
                webView,
                new FrameLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(container);

        if (savedInstanceState == null) {
            webView.loadUrl(startUrl());
        } else {
            webView.restoreState(savedInstanceState);
        }
    }

    private String startUrl() {
        String configured = BuildConfig.SITE_URL;
        if (configured == null || configured.trim().isEmpty()) {
            return OFFLINE_HOME;
        }
        return configured.trim();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        webView.saveState(outState);
    }

    /** Back walks the page history first and only then leaves the activity. */
    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK && webView.canGoBack()) {
            webView.goBack();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    /**
     * Replaces the WebView with a readable message when the page cannot be
     * loaded, so a failed launch does not look like a frozen white screen.
     */
    private void showError(String url, String description) {
        TextView message = new TextView(this);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        message.setPadding(pad, pad, pad, pad);
        message.setGravity(Gravity.CENTER);
        message.setTextSize(16f);
        message.setTextColor(Color.parseColor("#222939"));
        message.setText(getString(R.string.load_error, url, description));
        setContentView(message);
    }

    private class ShellWebViewClient extends WebViewClient {

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            Uri uri = request.getUrl();
            String scheme = uri.getScheme();
            if (scheme == null) {
                return false;
            }
            if (scheme.equals("http") || scheme.equals("https")) {
                // Keep normal links inside the shell.
                return false;
            }
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
            } catch (ActivityNotFoundException ignored) {
                // No app can handle this scheme; ignore the tap.
            }
            return true;
        }

        @Override
        public void onReceivedError(
                WebView view, WebResourceRequest request, WebResourceError error) {
            if (request.isForMainFrame()) {
                showError(
                        String.valueOf(request.getUrl()),
                        error == null ? "unknown error" : String.valueOf(error.getDescription()));
            }
        }
    }
}
