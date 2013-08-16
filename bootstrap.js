const {classes:Cc, interfaces:Ci, utils:Cu} = Components;

Cu.import('resource://gre/modules/Services.jsm');
const certdb = Cc['@mozilla.org/security/x509certdb;1']
                  .getService(Ci.nsIX509CertDB);
const log = function(msg) Services.console.logStringMessage(msg);

const CNNICAbbr = 'CNNIC';
const CNNICFull = 'China Internet Network Information Center';

var certObserver = {
  observe: function(subject, topic, data) {
    let httpChannel = subject.QueryInterface(Ci.nsIHttpChannel);
    if (!(httpChannel.loadFlags & Ci.nsIChannel.LOAD_INITIAL_DOCUMENT_URI)) {
      return;
    }

    let uri = httpChannel.URI.asciiSpec;
    let securityInfo = httpChannel.securityInfo;
    if (securityInfo === null) {
      return;
    }

    let serverCert =
      securityInfo.QueryInterface(Ci.nsISSLStatusProvider).SSLStatus
                  .QueryInterface(Ci.nsISSLStatus).serverCert;
    while (serverCert.issuer && !serverCert.issuer.equals(serverCert)) {
      if (serverCert.nickname.indexOf(CNNICAbbr) > -1 ||
          serverCert.nickname.indexOf(CNNICFull) > -1) {
        //log('542689: ' + uri + ' uses CNNIC cert');
        Services.prompt.alert(null, 'Bug 542689:', uri + ' uses CNNIC cert');
        break;
      }
      serverCert = serverCert.issuer;
    }
  }
};

function startup(data, reason) {
  Services.obs.addObserver(certObserver, 'http-on-examine-response', false);
}
function shutdown(data, reason) {
  Services.obs.removeObserver(certObserver, 'http-on-examine-response');
}
function install(data, reason) {
  let certNicks = {};
  certdb.findCertNicknames(null, Ci.nsIX509Cert.CA_CERT, {}, certNicks);
  certNicks = certNicks.value;
  let prefBranch = Services.prefs.getBranch('extensions.bug542689.');
  for (var i = 0, l = certNicks.length; i < l; i++) {
    if (certNicks[i].indexOf(CNNICAbbr) == -1 &&
        certNicks[i].indexOf(CNNICFull) == -1) {
      continue;
    }
    let certNick = certNicks[i].split(/\x01/);
    let certDBKey = certNick[certNick.length - 1];
    try {
      let cert = certdb.findCertByDBKey(certDBKey, null);
      let certOrig = (certdb.isCertTrusted(cert, Ci.nsIX509Cert.CA_CERT,
                          Ci.nsIX509CertDB.TRUSTED_SSL)
                        ? Ci.nsIX509CertDB.TRUSTED_SSL
                        : Ci.nsIX509CertDB.UNTRUSTED)
                   | (certdb.isCertTrusted(cert, Ci.nsIX509Cert.CA_CERT,
                          Ci.nsIX509CertDB.TRUSTED_EMAIL)
                        ? Ci.nsIX509CertDB.TRUSTED_EMAIL
                        : Ci.nsIX509CertDB.UNTRUSTED)
                   | (certdb.isCertTrusted(cert, Ci.nsIX509Cert.CA_CERT,
                          Ci.nsIX509CertDB.TRUSTED_OBJSIGN)
                        ? Ci.nsIX509CertDB.TRUSTED_OBJSIGN
                        : Ci.nsIX509CertDB.UNTRUSTED);
      if (certOrig != Ci.nsIX509CertDB.UNTRUSTED) {
        log('542689: distrust ' + cert.nickname);
        prefBranch.setIntPref(cert.dbKey, certOrig);
        certdb.setCertTrust(cert, Ci.nsIX509Cert.CA_CERT,
          Ci.nsIX509CertDB.UNTRUSTED);
      } else {
        log('542689: ' + cert.nickname + ' already untrusted');
      }
    } catch(e) {
      log('542689: ' + certNick + ' ' + e);
    }
  }
}
function uninstall(data, reason) {
  let prefBranch = Services.prefs.getBranch('extensions.bug542689.');
  let dbKeys = prefBranch.getChildList('', {});
  for (var i = 0, l = dbKeys.length; i < l; i++) {
    let dbKey = dbKeys[i];
    if (prefBranch.prefHasUserValue(dbKey)) {
      let cert = certdb.findCertByDBKey(dbKey, null);
      log('542689: resume trust of ' + cert.nickname);
      certdb.setCertTrust(cert, Ci.nsIX509Cert.CA_CERT,
        prefBranch.getIntPref(dbKey));
    }
  }
  prefBranch.deleteBranch('');
}
