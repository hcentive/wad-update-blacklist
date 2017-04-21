/* Updates WAF IP blacklists from DynamoDB IPBlacklist table */

var async = require('async');
var _ = require('underscore');
var aws = require('aws-sdk');
var fw = require('./lib/waf.js');
var db = require('./lib/dynamodb.js');

// fw.getSignatures(1, null, callback);
// fw.getIPBlacklists(1, null, callback);

// exports.handler = function(event, context) {
var updateFirewall = function(callback) {
  db.getActiveIPRecords(function (err, iprecords) {
    if (err) {
      console.log(err, null);
    } else {
      console.log(iprecords.Items.length + " active records in IP database");
      if (iprecords.Items) {
        var groupedBySrc = _.groupBy(iprecords.Items, 'SourceRBL');
        var addrMap = _.map(groupedBySrc, function(val, key) { return [key, val.map(function(o) {
          if (o.IPAddress.indexOf('/') === -1) {
            return o.IPAddress + '/32';
          } else {
            return o.IPAddress;
          }
        })];});

        async.eachSeries(addrMap, function(addr, callback) {
          // console.log(addr[0]);
          fw.updateBlacklists(addr[1], addr[0], (e, r) => {
            if (e) {
              callback(e, null);
            } else {
                callback();
            }
          });
        },
        function (err) {
          if (err) {
            console.log(err, err.stack)
          } else {
            console.log("Done!");
          }
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
