// Synthetic React Native bundle fixture for RN_001 unit tests.
// Contains one positive example of each detector category and one
// negative example for the AsyncStorage / cleartext-URL checks so the
// regex precision can be exercised end-to-end.

var Auth = {
  saveLoginToken: function (token) {
    // Sensitive key — must be flagged INSECURE_STORAGE.
    return AsyncStorage.setItem('auth_token', token);
  },
  saveTheme: function (theme) {
    // Benign key — must NOT be flagged.
    return AsyncStorage.setItem('theme_pref', theme);
  },
  saveJwt: function (jwt) {
    // Another sensitive key — flagged.
    return EncryptedStorage.setItem('jwt', jwt);
  },
};

var API = {
  // Cleartext URL — must be flagged CLEARTEXT_TRAFFIC.
  loginEndpoint: 'http://api.example.com/v1/login',
  // Loopback — must NOT be flagged (dev convenience).
  devOnly:       'http://localhost:8080/whoami',
  // Emulator host — must NOT be flagged.
  emulator:      'http://10.0.2.2:3000/echo',
  // HTTPS — must NOT be flagged.
  prod:          'https://api.example.com/v1/login',
};

// Hardcoded secrets — both must fire.
var AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
var FIREBASE_KEY   = 'AIzaSyA-EXAMPLEKEYTHIRTYFIVECHARACTERSX';

// WebView with both warning signals — strongest WV finding.
function renderWebView(uriProp) {
  return (
    <WebView
      source={{uri: uriProp}}
      originWhitelist={['*']}
      javaScriptEnabled={true}
    />
  );
}

// dangerouslySetInnerHTML — LOW finding.
function renderNote(html) {
  return <div dangerouslySetInnerHTML={{__html: html}} />;
}
