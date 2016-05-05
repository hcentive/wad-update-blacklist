var async = require('async');
var path = require('path');
var fs = require('fs');
var aws = require('aws-sdk');

var waf = new aws.WAF();

var wafConf = JSON.parse(fs.readFileSync(path.join('.', 'conf', 'waf.json')));

var IPSetDescriptor = function(type, value) {
  this.Type = type;
  this.Value = value;
};

var IPSet = function(id, name, descriptors){
  this.id = id;
  this.name = name;
  this.ipSetDesctiptors = [] || descriptors;
};

IPSet.prototype.getIPSetDescriptors = function() {
  this.ipSetDesctiptors.forEach(function(item, index, array) {
    console.log("Type: " + item.type);
    console.log("Value: " + item.value);
  });
};

IPSet.prototype.addIPSetDescriptors = function(type, value) {
  var ipsetdesc = new IPSetDescriptor(type, value);
  this.ipSetDesctiptors.push(ipsetdesc);
};

var filterIPv4Indicators = function(result) {
  var indicator = _.where(result.indicators, {type: "IPv4"});
  indicator.forEach(function(i){
    console.log(i.indicator);
  });
};

var ipSet = function(ipsetid, callback) {
  console.log("Getting IPSet for - " + ipsetid);
  waf.getIPSet({IPSetId: ipsetid}, function(err, ipset) {
    if (err != null) {
      callback(err, null);
    }
    callback(null, ipset);
  });
};

var ipSetByName = function(ipsetname, callback) {
  console.log("Getting IPSet " + ipsetname);
  var params = {Limit: wafConf.ipSetLimit};

  waf.listIPSets(params, function(err, ipsets) {
    if (err) {
      callback(err, null);
    } else {
      if (ipsets.IPSets.length > 0) {
        ipsets.IPSets.forEach(function(ipset) {
          if (ipset.Name.toLowerCase() === ipsetname) {
            console.log("Found IP set " + ipset.Name + "(" + ipset.IPSetId + ")");
            callback(null, ipset);
          }
        });
      } else {
        callback(null, null);
      }
    }
  });
};

//get all IP addresseses in IPMatch rules
var getAddressesInRules = function(limit, nextMarker, callback, addresses) {
  addresses = addresses || [];
  // console.log("begin - " + addresses.length);
  var params = {};
  if (nextMarker != null) {
    params = {Limit: limit, NextMarker: nextMarker};
  } else {
    params = {Limit: limit};
  }
  waf.listRules(params, function(err, rules) {
    if (err) {
      callback(err, null);
    } else {

      if (rules.Rules.length > 0) {
        rules.Rules.forEach(function(rule){
          // console.log(rule);
          waf.getRule({RuleId: rule.RuleId}, function(err, r) {
            var ruleName = r.Rule.Name;
            r.Rule.Predicates.forEach(function(predicate){
              // console.log(predicate.Type);
              if (predicate.Type === "IPMatch" && ruleName.toLowerCase().startsWith("ipblacklist")) {
                waf.getIPSet({IPSetId: predicate.DataId}, function(err, ipset) {
                  var ipSetId = ipset.IPSet.IPSetId;
                  var ipSetName = ipset.IPSet.Name;
                  var ipSetDescriptors = ipset.IPSet.IPSetDescriptors;
                  // console.log('IP Set ' + ipSetName + ' currently has ' + ipSetDescriptors.length + ' descriptors');
                  ipSetDescriptors.forEach(function (ipSetDescriptor) {
                    if (addresses.indexOf(ipSetDescriptor.Value) === -1) {
                      addresses.push(ipSetDescriptor.Value);
                    }
                  });
                  // console.log("predicates loop - " + addresses.length);
                  var nm = rules.NextMarker;
                  getAddresses(limit, nm, callback, addresses);
                });
              }
            });
          });
        });
        // console.log("addresses " + addresses.length);
        callback(null, addresses);
      }
    }
  });
};

//get all IP addresses in blacklists
var getRBLAddresses = function(limit, nextMarker, callback, addresses) {
  addresses = addresses || [];
  // console.log("begin - " + addresses.length);
  var params = {};
  if (nextMarker != null) {
    params = {Limit: limit, NextMarker: nextMarker};
  } else {
    params = {Limit: limit};
  }

  waf.listIPSets(params, function(err, ipsets) {
    if (err) {
      callback(err, null);
    } else {
      var nm = ipsets.NextMarker;
      if (ipsets.IPSets.length > 0) {
        ipsets.IPSets.forEach(function(ipset) {
          var ipSetId = ipset.IPSetId;
          var ipSetName = ipset.Name;

          if (ipSetName.toLowerCase().startsWith(wafConf.ipsetPrefix)) {
            console.log("Looking up addresses for " + ipSetName);
            waf.getIPSet({IPSetId: ipSetId}, function(err, ips) {
              var ipSetDescriptors = ips.IPSet.IPSetDescriptors;
              ipSetDescriptors.forEach(function (ipSetDescriptor) {
                if (addresses.indexOf(ipSetDescriptor.Value) === -1) {
                  addresses.push(ipSetDescriptor.Value);
                }
              });
              console.log("Done adding addresses for " + ipSetName + " to rblmap.");
            });
          }
        });
      }
      if (nm != null) {
        console.log("Found NextMarker. Get more IPSets.");
        getRBLAddresses(limit, nm, callback, addresses);
      } else {
        console.log("Done creating rblmap.");
        callback(null, addresses);
      }
    }
  });
};

//returns a map of RBLs with rbl name as the key and addresses as the value
var getRBLMap = function(limit, nextMarker, callback, rblmap) {
  rblmap = rblmap || new Map();
  var params = {};
  if (nextMarker != null) {
    params = {Limit: limit, NextMarker: nextMarker};
  } else {
    params = {Limit: limit};
  }

  // console.log("Get IPSets");
  waf.listIPSets(params, function(err, ipsets) {
    if (err) {
      callback(err, null);
    } else {
      // console.log("Found " + ipsets.IPSets.length + " IPSets.");
      var nm = ipsets.NextMarker;
      if (ipsets.IPSets.length > 0) {
        ipsets.IPSets.forEach(function(ipset) {
          var ipSetId = ipset.IPSetId;
          var ipSetName = ipset.Name;

          // console.log("IPSetName - " + ipSetName);
          if (ipSetName.toLowerCase().startsWith(wafConf.ipsetPrefix)) {
            console.log("Looking up addresses for " + ipSetName);
            var addresses = [];
            waf.getIPSet({IPSetId: ipSetId}, function(err, ips) {
              var ipSetDescriptors = ips.IPSet.IPSetDescriptors;
              ipSetDescriptors.forEach(function (ipSetDescriptor) {
                if (addresses.indexOf(ipSetDescriptor.Value) === -1) {
                  addresses.push(ipSetDescriptor.Value);
                }
              });
              rblmap.set(ipSetName, addresses);
              // console.log("Done adding addresses for " + ipSetName + " to rblmap.");
              if (nm != null) {
                console.log("Found NextMarker. Get more IPSets.");
                getRBLMap(limit, nm, callback, rblmap);
              }
            });
          }
        });
        if (nm != null) {
          console.log("Found NextMarker. Get more IPSets.");
          getRBLMap(limit, nm, callback, rblmap);
        } else {
          console.log("Done creating rblmap. Number of lists = " + rblmap.size);
          callback(null, rblmap);
        }
      }
    }
  });
};

var createIPSet = function(ipSetName, callback) {
  // to create an IPSet, obtain a change token first
  waf.getChangeToken({}, function (err, response) {
    if (err) {
      callback(err, null);
    } else {
      // console.log(response);
      waf.createIPSet({
        ChangeToken: response.ChangeToken,
        Name: ipSetName
      }, function(E, D) {
        if (E) {
          console.error('Error creating IP set ' + ipSetName, E);
          callback(E, null);
        } else {
          console.log('Created IP set ' + D.IPSet.Name);
          callback(null, D);
        }
      });
    }
  });
};

var updateIPSet = function(ipset, updates, callback) {
  //to update an IP set, obtain a change token first
  waf.getChangeToken({}, function(err, response) {
    if (err) {
      callback(err, null);
    } else {
      // console.log(resp);
      console.log('Updating IP set ' + ipset.IPSetId + ' with ' + updates.length + ' updates');
      // console.log(response);
      waf.updateIPSet({
          ChangeToken: response.ChangeToken,
          IPSetId: ipset.IPSetId,
          Updates: updates
      }, function(E, D) {
        if (E) {
          console.log("Error updating IPSet " + ipset.IPSetId, E);
          callback(E, null);
        } else {
          console.log("Updated IPSet " + ipset.IPSetId);
          callback(null, ipset);
        }
      });
    }
  });
};

var updateIPSetByName = function(ipsetname, updates, callback) {
  ipSetByName(ipsetname, function(err, ipset) {
    if (err) {
      callback(err, null);
      return;
    }
    updateIPSet(ipset, updates, callback);
  });
};

// Searches for IP addresses in blacklists;
// if not found updates the respective blacklist for the source with addresses.
// Creates new IPSets if needed.
var createOrUpdateRBLs = function(addresses, source, callback) {
  async.waterfall([
    function(cback) {
      var params = {Limit: 1};
      //update existing IP sets if they have capacity. AWS limits IP sets to 1000 IP desciptors.
      var ipSets = [];
      (function createIPSetArray() {
        waf.listIPSets(params, function(err, ipsets) {
          if (err) {
            cback(err, null);
          } else {
            var nm = ipsets.NextMarker;
            ipsets.IPSets.forEach(function(ipset) {
              if(ipset.Name.toLowerCase().startsWith(wafConf.ipsetPrefix))
              ipSets.push(ipset);
            });
          }
          if (nm != null) {
            params = {Limit: 1, NextMarker: nm};
            createIPSetArray();
          } else {
            // console.log("ipSets = " + ipSets.length);
            cback(null, ipSets);
          }
        });
      })();
    },
    function (data, cback) {
      async.map(data, function (ipset, cb) {
        waf.getIPSet({ IPSetId: ipset.IPSetId }, cb);
      },
      function (err, ips) {
        if (err) {
            console.error('Error getting IP set', err);
            // cback(err, null);
        } else {
          ips = ips.map(function (ip) {
              return ip.IPSet;
          });
          // console.log(ips.length + ' IP Sets in total');
        }
        cback(err, ips);
      });
    }
  ], function(err, results) {
    if (err) {
      callback(err, null);
    } else {
      var updates = [];
      // search for addresses in blacklists for 'source'
      // blacklist naming convention - 'ipblacklist-{source}-{RBLnumber}' e.g. ipblacklist-alienvault-1
      for (var i = 0; i < addresses.length; i++) {
        var address = addresses[i];
        var found = false;
        results.forEach(function(rbl) {
          rblname = rbl.Name;
          if (rblname.indexOf(source) != -1) {
            var ipSetDescriptors = rbl.IPSetDescriptors.map(function(ipsetdesc) { return ipsetdesc.Value});
            ipSetDescriptors.forEach(function(descriptor) {
              if (descriptor === address) {
                // console.log("Found " + address + " in " + rblname);
                found = true;
                addresses.splice(i, 1);
              }
            });
          }
        });
        // if address is not found in the addresses, insert it
        if (!found) {
          // console.log("Adding " + address + " to updates array");
          var ipSetDescriptor = new IPSetDescriptor('IPV4', address);
          updates.push({ Action: 'INSERT', IPSetDescriptor: ipSetDescriptor });
        }
      }

      // WAF updates are limited to 1000 per IPSet. If number of updates is greater than that, batch them.
      // Look for RBLs that have capacity, and add addresses to them. Create new RBLs for leftovers.
        async.waterfall([
          function(cb) {
            async.map(results, function(rbl, c) {
              rblname = rbl.Name;
              if (rblname.indexOf(source) != -1) {
                var ipSetDescriptors = rbl.IPSetDescriptors.map(function(ipsetdesc) { return ipsetdesc.Value});
                var leftoverCount = wafConf.maxDescriptorsPerIpSetUpdate - ipSetDescriptors.length;
                if (leftoverCount > 0) {
                  if (updates.length > 0) {
                    // console.log("Updating " + rblname + " with leftover count " + leftoverCount);
                    var updateBatch = updates.splice(0, leftoverCount);
                    updateIPSet(rbl, updateBatch, function (err, res) {
                      if (err) {
                        console.error('Error updating IP set ' + ipSet.Name, err);
                        c(err, null);
                        return;
                      } else {
                        console.log('Updated IP set ' + rblname + " with " + updateBatch.length + " IP desciptors");
                        c(null, res);
                      }
                    });
                  }
                }
              }
            }, function(e, r) {
              console.log("Calling cb");
              cb(e, r);
            });
          },
          function(cb) {
            console.log("Pending updates - " + updates.length);
            if (updates.length > 0) {
              // get count of IP set RBLs and set rblCount
              rblCount = results.length;
              // console.log("number of RBLs - " + rblCount);
              var ipSetName = wafConf.ipsetPrefix + "-" + source + "-" + (rblCount + wafConf.ipsetIncrementBy);
              (function newIPSet(cb) {
                console.log("Creating new IPSet - " + ipSetName);
                createIPSet(ipSetName, function (e, d) {
                  if (e) {
                    cb(e, null);
                    return;
                  }
                  var updateBatch = updates.splice(0, wafConf.maxDescriptorsPerIpSet);
                  // update the newly created IPset with IP desciptors
                  updateIPSet(d.IPSet, updateBatch, function (e, d) {
                    if (e) {
                      cb(e, null);
                      return;
                    } else {
                      // Update IPBlackListRule with new IPSet
                      waf.getChangeToken({}, function(err, response) {
                        if (err) {
                          callback(err, null);
                        } else {
                          var p = {
                            RuleId: wafConf.blacklistRuleID,
                            ChangeToken: response.ChangeToken,
                            Updates: [{
                              Action: 'INSERT',
                              Predicate: {
                                DataId: d.IPSetId,
                                Negated: true,
                                Type: 'IPMatch'
                              }
                            }]
                          };
                          waf.updateRule(p, function(E, D) {
                            if (E) {
                              cb(E, null);
                              return;
                            }
                            if (updates.length > 0) {
                              rblCount++;
                              ipSetName = wafConf.ipsetPrefix + "-" + source + "-" + (rblCount + wafConf.ipsetIncrementBy);
                              newIPSet(cb);
                            }
                          });
                        }
                      });
                    }
                  });
                });
              })();
            }
          }
        ], function(e, d) {
          callback(e, d);
        });
      }
    }
  );
};

exports.getSignatures = (limit, nextMarker, callback) => {
  getRBLAddresses(limit, nextMarker, callback, null);
};

exports.getIPBlacklists = (limit, nextMarker, callback) => {
  getRBLMap(limit, nextMarker, callback, null);
};

exports.updateBlacklists = (addresses, source, callback) => {
  createOrUpdateRBLs(addresses, source, callback);
};
