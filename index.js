/* Updates WAF IP blacklists from DynamoDB IPBlacklist table */

var async = require('async');
var _ = require('underscore');
var aws = require('aws-sdk');
var fw = require('./lib/waf.js');
var db = require('./lib/dynamodb.js');

// fw.getSignatures(1, null, callback);
// fw.getIPBlacklists(1, null, callback);

var updateFirewall = function(callback) {
  db.getActiveIPRecords(function (err, iprecords) {
    if (err) {
      cback(err, null);
    } else {
      if (iprecords.Items) {        
        var groupedBySrc = _.groupBy(iprecords.Items, 'SourceRBL');
        var addrMap = _.map(groupedBySrc, function(val, key) { return [key, val.map(function(o) { return o.IPAddress; })];});
        addrMap.forEach(function (addr) {
          fw.updateBlacklists(addr[1], addr[0], callback);
        });
      }
    }
  });
};

updateFirewall(callback);

function callback(err, data) {
  if (err) {
    console.log(err, err.stack);
  } else {
    console.log(data);
  }
}

// exports.handler = function(event, context) {

  // waf.getIPSet({IPSetId: config.ipSetId}, function(err, ipset){
  //   if (err != null) {
  //     console.log(err);
  //     return;
  //   }
  //   updateAVBlacklist(config.otx_start_path, ipset);
  // });
// };
