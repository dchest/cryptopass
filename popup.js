SCRYPT_N = 32768;
SCRYPT_r = 8;
SCRYPT_p = 1;

function addSessionState(key, value) {
  var d = chrome.extension.getBackgroundPage().data;
  if (!d) {
    d = {};
    chrome.extension.getBackgroundPage().data = d;
  }
  d[key] = value;
}

function getSessionState(key, default_value) {
  var d = chrome.extension.getBackgroundPage().data;
  if (d) {
    return d[key];
  }
  return default_value;
}

function hashPassword(password, salt, length) {
  var x = btoa(
        String.fromCharCode.apply(null, scrypt.crypto_scrypt(
            scrypt.encode_utf8(password),
            scrypt.encode_utf8(salt),
            SCRYPT_N,
            SCRYPT_r,
            SCRYPT_p,
            length)));
  return x;
}

// Return the normalized significant part of the host name of the URL.
function getSignificantDomain(url) {
  var l = document.createElement("a");
  l.href = url;
  return publicsuffix.getSignificantDomain(l.hostname);
}

// Persist the value of an element specified by ID in the synchronized storage.
function persistInSyncedStorageElementValue(element_id) {
  return function(event) {
    var elem = document.getElementById(element_id);
    if (elem && elem.value) {
      var v = elem.value;
      // This is a real hack. Because chrome sync storage doesn't let you
      // (as far as I can tell) access the keys programmatically--i.e., with
      // anything other than a string literal--I store all the prefs in a
      // single 'prefs' dict. Kind of lame, but it makes for shorter code than
      // duplicating all this persist/restore logic in three different event
      // handlers.
      chrome.storage.sync.get({'prefs':{}}, function(items) {
        items.prefs[element_id] = v;
        chrome.storage.sync.set({'prefs':items.prefs}, function(){});
      });
    }
    return false;
  }
}

// Fill an element specified by ID with the value stored in sync'ed storage.
function fillFromSyncedStorageElementValue(element_id, default_value) {
  var elem = document.getElementById(element_id);
  chrome.storage.sync.get({'prefs':{}},
    function(items) {
      var val = items.prefs[element_id]||'';
      elem.value = val;
    });
}

// Show a warning to the user.
function showWarning(warning_string) {
  document.querySelector('#warning-box').innerHTML = warning_string;
  showDiv('warning-box');
}

function showPleaseWait() {
  showDiv('result-box');
  document.querySelector("#result-box").innerHTML =
    '<p class="working">Please wait...</p>';
}

// Special handling of password. We persist the value only in the session
// state, and persist in sync'ed storage a hash that we can check against.
function onPasswordChange() {
  setTimeout(function(){
    var password = document.getElementById('password').value;
    addSessionState('password', password);
    chrome.storage.sync.get({'master_password_hash':'', 'salt':'hardcoded_SALT'},
      function(items) {
      var hash = hashPassword(password, items.salt, 2);
      if (items.master_password_hash && items.master_password_hash != hash) {
        // For now, just save the hash in the session state. If we use a password
        // from this hash, we will treat the new hash as the correct hash.
        addSessionState('current_master_password_hash', hash);
        showWarning('Password does not match stored hash.');
      } else {
        showWarning('');
      }
      if (items.master_password_hash) {
        // Forget any old/new hash so we don't save it in settings. Presence of a
        // non-false value for this variable indicates a pending write to the
        // saved settings.
        addSessionState('current_master_password_hash', false);
      } else {
        addSessionState('current_master_password_hash', hash);
      }
    });
  }, 5);
}

function stringXor(a, b) {
  var r = "";
  var longer = a.length > b.length ? a : b;
  var shorter = a.length < b.length ? a : b;
  for (i = 0; i < shorter.length; i++) {
    r += String.fromCharCode(a.charCodeAt(0) ^ b.charCodeAt(0));
  }
  r += longer.substr(shorter.length);
  return r;
}

function generatePassword(callback) {
  var master_password = document.getElementById('password').value;
  var salt = document.getElementById('salt').value;
  var username = document.getElementById('username').value;
  var url = document.getElementById('url').value;
  var length = document.getElementById('length').value;
  // Generate password.
  var password = hashPassword(master_password,
                              stringXor(salt, stringXor(username, url)),
                              // Hack: generate a password twice the length
                              // and remove non-base62 chars, then shorten.
                              2*length);
  password = password.replace(/[^A-Za-z0-9]/gm, '').substr(length);
  callback(password);
  // And finally, save the new master password hash in the settings, if needed.
  var current_hash = getSessionState('current_master_password_hash');
  if (current_hash) {
    chrome.storage.sync.set({'master_password_hash':current_hash},
      function(){});
  }
}

function showPassword(event) {
  setTimeout(function(){
    showPleaseWait();
    generatePassword(function(password){
      document.querySelector("#result-box").innerHTML =
        '<p>Your password:<br/>' +
        '<input type="text" spellcheck="false" class="center" id="result"' +
        'value="' + password + '"/></p>';
      document.getElementById("result").select();
    })}, 5);
  event.preventDefault();
  event.stopPropagation();
  return false;
}

function fillPassword(event) {
  setTimeout(function(){
    showPleaseWait();
    generatePassword(function(password){
      document.querySelector("#result-box").innerHTML =
        "<span class='gray'>Done!</span>";
      var username = document.getElementById('username').value;
      chrome.tabs.executeScript(null,
      {code:'var els = document.getElementsByTagName("input"); ' +
            'for (var i = 0; i < els.length; i++) { ' +
            '  if (els[i].type.toLowerCase() == "password") { ' +
            '    els[i].value = "' + password + '"; ' +
            '  } else if (els[i].type.toLowerCase() == "text" && ' +
            '             els[i].name.toLowerCase().match(' +
            '               /login|username|email|user/)) { ' +
            '    els[i].value = "' + username + '"; ' +
            '  } ' +
            '}'},
            function(){
              if (!event) {
                // This was sent from an 'enter' keypress
                setTimeout(function(){ window.close(); }, 500);
              }
            });

    })}, 5);
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  return false;
}

function toggleDiv(id)
{
    var infoStyle = document.getElementById(id).style;
    if (infoStyle.display == "block")
        infoStyle.display = "none";
    else
        infoStyle.display = "block";
}

function showDiv(id) {
  var infoStyle = document.getElementById(id).style;
  infoStyle.display = "block";
}

function hideDiv(id) {
  var infoStyle = document.getElementById(id).style;
  infoStyle.display = "none";
}

function toggleOptions(event) {
  var s = !getSessionState('options_shown');
  addSessionState('options_shown', s);
  if (s) {
    showDiv('options');
  } else {
    hideDiv('options');
  }
  return false;
}

document.addEventListener('DOMContentLoaded', function () {
  // Hide options on first load
  if (!getSessionState('options_shown')) {
    hideDiv('options');
  }
  // Set up event handlers
  document.querySelector('#main-form').addEventListener('keydown',
  function(e){
    if (e.which == 13) {
      fillPassword();
    }
  });
  document.querySelector('#show-button').addEventListener('click',
    showPassword);
  document.querySelector('#fill-button').addEventListener('click',
    fillPassword);
  document.querySelector('#options-button').addEventListener('click',
    toggleOptions);
  document.querySelector('#password').addEventListener('change',
    onPasswordChange);
  document.querySelector('#salt').addEventListener('blur',
    persistInSyncedStorageElementValue('salt'));
  document.querySelector('#username').addEventListener('blur',
    persistInSyncedStorageElementValue('username'));
  document.querySelector('#length').addEventListener('blur',
    persistInSyncedStorageElementValue('length'));

  // Put website URL into box.
  chrome.tabs.getCurrent(function(tab) {
    chrome.tabs.query(
      {active: true, windowId: chrome.windows.WINDOW_ID_CURRENT},
      function(tabs) {
        document.querySelector('#url').value =
          getSignificantDomain(tabs[0].url);
      });
  });

  // Fill settings.
  fillFromSyncedStorageElementValue('salt', '');
  fillFromSyncedStorageElementValue('username', '');
  fillFromSyncedStorageElementValue('length', '16');

  // Get cached password.
  password = getSessionState('password', '');
  document.getElementById('password').value = password;
  document.querySelector('#password').focus();
});
