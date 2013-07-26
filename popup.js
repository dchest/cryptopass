function makePassword() {
    var password = document.getElementById('secret').value;
    var username = document.getElementById('username').value;
    var url = document.getElementById('url').value;
    var length = document.getElementById('length').value;
    var salt = document.getElementById('salt').value;
    var result_field = document.getElementById('result');

    // Save settings
    chrome.storage.sync.set({'username':username, 'salt':salt, 'length':length}, function(){});
    var r = scrypt.crypto_scrypt(
      scrypt.encode_utf8(password),
      // TODO: is this a safe way to generate salt?
      scrypt.encode_utf8(secret + url + username),
      // TODO: do something other than this hack for output length
      32768, 8, 1, 128);
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
        document.querySelector("#result-box").innerHTML = 
            '<p class="centered">Your password <span class="gray">(copy and paste it)</span>:<br>'+
            '<input type="text" spellcheck="false" class="centered" id="result" value=""></p>'+
            '<div id="warning">Secret should contain at least 16 characters for better security.</div>';
        var result_field = document.getElementById('result');
        result_field.value = makePassword();
        if (document.querySelector('#secret').value.length < 16)
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
  toggleDiv("options1");
  toggleDiv("options2");
}

document.addEventListener('DOMContentLoaded', function () {
  //hideDiv("options1");
  //hideDiv("options2");
  document.querySelector('#main-form').addEventListener('keydown', function(e){ if (e.which == 13) { fillPassword(); }});
  document.querySelector('#show-button').addEventListener('click', generatePassword);
  document.querySelector('#fill-button').addEventListener('click', fillPassword);
  //document.querySelector('#options-button').addEventListener('click', showHideOptions);
  document.querySelector('#secret').addEventListener('keydown', colorPasswordField);
  document.querySelector('#secret').addEventListener('input', colorPasswordField);

  // Put website URL into box.
  chrome.tabs.getCurrent(function(tab) {
    chrome.tabs.query({active: true, windowId: chrome.windows.WINDOW_ID_CURRENT}, function(tabs) {
        document.querySelector('#url').value = getSignificantDomain(getHostname(tabs[0].url));
      });
  });

  // Fill settings.
  chrome.storage.sync.get({'username':'', 'length':'16', 'salt':''}, function(items){
    document.getElementById('username').value = items.username;
    document.getElementById('salt').value = items.salt;
    document.getElementById('length').value = items.length;
  });

  document.querySelector('#secret').focus();
});
