const {classes:Cc, interfaces:Ci, utils:Cu} = Components;

Cu.import('resource://gre/modules/Services.jsm');
const certdb = Cc['@mozilla.org/security/x509certdb;1']
                  .getService(Ci.nsIX509CertDB);

function startup(data, reason) {}
function shutdown(data, reason) {}
function install(data, reason) {
  let certNicks = {};
  certdb.findCertNicknames(null, Ci.nsIX509Cert.CA_CERT, {}, certNicks);
  certNicks = certNicks.value;
  let prefBranch = Services.prefs.getBranch('extensions.bug542689.');
  for (var i = 0, l = certNicks.length; i < l; i++) {
    if (certNicks[i].indexOf('CNNIC') == -1) {
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
        prefBranch.setIntPref(cert.dbKey, certOrig);
        certdb.setCertTrust(cert, Ci.nsIX509Cert.CA_CERT,
          Ci.nsIX509CertDB.UNTRUSTED);
      } else {
        Services.console.logStringMessage('542689: ' + certNick + ' untrusted');
      }
    } catch(e) {
      Services.console.logStringMessage('542689: ' + certNick + ' ' + e);
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
      certdb.setCertTrust(cert, Ci.nsIX509Cert.CA_CERT,
        prefBranch.getIntPref(dbKey));
    }
  }
  prefBranch.deleteBranch('');
}
