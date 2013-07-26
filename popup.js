function sessionState() {
  var d = chrome.extension.getBackgroundPage().data;
  if (d) {
    return d;
  }
  d = {};
  chrome.extension.getBackgroundPage().data = d;
  return d;
}

// Return a checksum that we can use to try to catch typoes.
function partialHashMasterPassword(password, salt) {
  // CRC32
  s = String(password+salt);
  var polynomial = 0x04C11DB7,
      initialValue = 0xFFFFFFF,
      finalXORValue = 0xFFFFFFFF,
      crc = initialValue,
      table = [], i, j, c;
 
  function reverse(x, n) {
    var b = 0;
    while (n) {
      b = b * 2 + x % 2;
      x /= 2;
      x -= x % 1;
      n--;
    }
    return b;
  }
 
  for (i = 255; i >= 0; i--) {
    c = reverse(i, 32);
 
    for (j = 0; j < 8; j++) {
      c = ((c * 2) ^ (((c >>> 31) % 2) * polynomial)) >>> 0;
    }
 
    table[i] = reverse(c, 32);
  }
 
  for (i = 0; i < s.length; i++) {
    c = s.charCodeAt(i);
    if (c > 255) {
      throw new RangeError();
    }
    j = (crc % 256) ^ c;
    crc = ((crc / 256) ^ table[j]) >>> 0;
  }
 
  // Cut in half, to REALLY make it low entropy. ;) 
  return btoa((crc ^ finalXORValue) >>> 0).substr(0,6);
}

function makePassword() {
    var password = document.getElementById('secret').value;
    var username = document.getElementById('username').value;
    var url = document.getElementById('url').value;
    var length = document.getElementById('length').value;
    var salt = document.getElementById('salt').value;

    // Save settings.
    chrome.storage.sync.set({'username':username,
                             'salt':salt,
                             'length':length}, function(){});
    // Cache password.
    sessionState()['secret'] = password;

    var r = scrypt.crypto_scrypt(
      scrypt.encode_utf8(password),
      // TODO: is this a safe way to generate salt?
      scrypt.encode_utf8(secret + url + username),
      // Kind of a hack. Generate 2x length because we have to strip out the
      // non-base62 base64 chars (so to speak).
      32768, 8, 1, 2*length);
    return btoa(String.fromCharCode.apply(null, r))
      .replace(/[^A-Za-z0-9]/gm, '')
      .substr(0, length);
}

function toggleDiv(id)
{
    var infoStyle = document.getElementById(id).style;
    if (infoStyle.display == "block")
        infoStyle.display = "none";
    else
        infoStyle.display = "block";
}

function showDiv(id)
{
    var infoStyle = document.getElementById(id).style;
    infoStyle.display = "block";
}

function hideDiv(id)
{
    var infoStyle = document.getElementById(id).style;
    infoStyle.display = "none";
}

function getHostname(str) {
    if (str == null || str == undefined)
        return "";
    var re = new RegExp('^(?:f|ht)tp(?:s)?\://(?:www.)?([^/]+)', 'im');
    var match = str.match(re);
    if (match != null && match.length > 0)
        return match[1].toString();
    else
        return "";
}

function showPleaseWait() {
    document.querySelector("#result-box").innerHTML = "<span class='working'>Please wait...</span>";
    showDiv('result-box');
}

function generatePassword(event)
{
    showPleaseWait();
    setTimeout(function() {
      var masterHash = sessionState()['master_hash'];
      var secretElement = document.querySelector('#secret');
      var secret = secretElement.value;
      var warning = '';

      newHash = partialHashMasterPassword(secret, document.getElementById('salt').value);
      if (masterHash && masterHash != '' &&
        newHash != masterHash) {
        // Hash mismatch--typoed master password!
        warning = '<div id="warning">Master password hash mismatch! Did you typo?</div>';
      } else if (secret.length < 8) {
        warning = '<div id="warning">Secret should contain at least 8 characters for better security.</div>';
      }
      // Set the master hash to the new hash, anyway.
      chrome.storage.sync.set({'master_hash':newHash}, function(){});
      sessionState()['master_hash'] = newHash;
      document.querySelector("#result-box").innerHTML = 
      '<p class="centered">Your password <span class="gray">(copy and paste it)</span>:<br>'+
      '<input type="text" spellcheck="false" class="centered" id="result" value=""></p>'+
      warning;
      var result_field = document.getElementById('result');
      result_field.value = makePassword();
      if (warning)
        showDiv('warning');
      else
        hideDiv('warning');
      result_field.select();
    }, 60);
    event.preventDefault();
    event.stopPropagation();
    return false;
}

function fillPassword() {
    showPleaseWait();
    document.querySelector("#main-form").style.display = "none";
    setTimeout(function() {
        var username = document.getElementById('username').value || "";
        chrome.tabs.executeScript(null,
            {code:"var els = document.getElementsByTagName('input'); \
                   for (var i=0; i < els.length; i++) { \
                     if (els[i].type.toLowerCase() == 'password') { \
                         els[i].value = '" + makePassword() + "'; \
                     } else { \
                         var name = els[i].name.toLowerCase(); \
                         if (name.match(/login|username|email|user/)) { \
                           els[i].value = '" + username + "'; \
                         } \
                     } \
                   }"});
      document.querySelector("#result-box").innerHTML = "<span class='gray'>Done!</span>";
      setTimeout(function() {
          window.close();
      }, 500);
  }, 50);
  event.preventDefault();
  return false;
}

hashColors = ["#CC0000", "#0000CC", "#00CC00", "#CC33CC", "#FF6600", "#66CCCC",
              "#3399FF", "#CC6666", "#999999"];

function colorPasswordField() {
    var secretElement = document.querySelector('#secret');
    var secret = secretElement.value;
    var color;
    if (secret.length > 8) {
        var h = 5381;
        for (var i = 0; i < secret.length; i++) {
            h = (((h << 5) + h) + secret.charCodeAt(i)) & 0xffffffff;
        }
        color = hashColors[h % hashColors.length];
    } else {
        color = "black";
    }
    secretElement.style.color = color;
}

function showHideOptions() {
  sessionState()['options_shown'] = !sessionState()['options_shown'];
  if (sessionState()['options_shown']) {
    showDiv('options');
  } else {
    hideDiv('options');
  }
}

document.addEventListener('DOMContentLoaded', function () {
  if (!sessionState()['options_shown']) {
    hideDiv("options");
  }
  document.querySelector('#main-form').addEventListener('keydown', function(e){ if (e.which == 13) { fillPassword(); }});
  document.querySelector('#show-button').addEventListener('click', generatePassword);
  document.querySelector('#fill-button').addEventListener('click', fillPassword);
  document.querySelector('#options-button').addEventListener('click', showHideOptions);
  document.querySelector('#secret').addEventListener('keydown', colorPasswordField());
  document.querySelector('#secret').addEventListener('input', colorPasswordField());

  // Put website URL into box.
  chrome.tabs.getCurrent(function(tab) {
    chrome.tabs.query({active: true, windowId: chrome.windows.WINDOW_ID_CURRENT}, function(tabs) {
        document.querySelector('#url').value = getSignificantDomain(getHostname(tabs[0].url));
      });
  });

  // Fill settings.
  chrome.storage.sync.get({'username':'', 'length':'16', 'salt':'', 'master_hash':''}, function(items){
    document.getElementById('username').value = items.username;
    document.getElementById('salt').value = items.salt;
    document.getElementById('length').value = items.length;
    sessionState()['master_hash'] = items.master_hash;
  });
  // Get cached password.
  secret = sessionState()['secret'];
  document.getElementById('secret').value = secret == null ? '' : secret;
  chrome.storage.sync.get({'username':'', 'length':'16', 'salt':''}, function(items){
    document.getElementById('username').value = items.username;
    document.getElementById('salt').value = items.salt;
    document.getElementById('length').value = items.length;
  });

  document.querySelector('#secret').focus();
});
