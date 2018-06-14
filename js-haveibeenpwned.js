/*
 * [js-haveibeenpwned]{@link https://github.com/}
 *
 * @version 0.1.0
 * @author Jason Watts [jwatts@gravitatesolutions.com]
 * @Copyright 2018 AIAA.org
 * @license MIT
 *
 * Prerequisites
 * [js-sha1]{@link https://github.com/emn178/js-sha1}
 * by Chen, Yi-Cyuan [emn178@gmail.com]
 * js-haveibeenpwned built against js-sha1 version 0.6.0
 * 
*/
(function() {
	var root = typeof window === 'object' ? window : 
  	(typeof self === 'object' ? self : {});
  var pwnedRangeEndpoint = "https://api.pwnedpasswords.com/range/";
  
  function checkPwnedPassword(pass, callback) {
  	var pwned = new HaveIBeenPwned();
    pwned.check(pass, callback);
  }
  
  function HaveIBeenPwned() {
  	this.hasErrors = false;
    
    if (!root.sha1) {
    	alert("SHA1 hashing required: https://github.com/emn178/js-sha1");
      this.hasErrors = true;
    }
  }
  
  HaveIBeenPwned.prototype.check = function(pass, callback) {
  	if (this.hasErrors) {
    	callback(false, -1, null);
      return;
    }
    
  	var sha1pass = sha1(pass).toUpperCase();
    var prefixSHA1 = sha1pass.substring(0, 5);
    var suffixSHA1 = sha1pass.substring(5);
    
  	var xmlHttp = new XMLHttpRequest();
    var responseText = "";
    var responseStatus = 0;
    
    xmlHttp.onreadystatechange = function() {
    	if (this.readyState === 4) {
    		responseStatus = xmlHttp.status;

        if (responseStatus === 200) {
        	responseText = xmlHttp.responseText;
          
          var matchCount = 0;
          var gotShaMatch = (responseText || '').indexOf(suffixSHA1) !== -1;
          
          if (gotShaMatch) {
            matchCount = Number(responseText
            	.split(suffixSHA1 + ':')[1]
              .split('\n')[0]
            );
          }
          callback(gotShaMatch, matchCount, responseText);
          
        } else {
          //api error
          callback(false, -1, null);
        }
      }
    };
    
    xmlHttp.open("GET", pwnedRangeEndpoint + prefixSHA1, true);
    xmlHttp.send();
  };

	//global access to HaveIBeenPwned checker
	root.haveIBeenPwned = checkPwnedPassword;
})();
