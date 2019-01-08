const addon = require('../build/Debug/node-creeper-native');
var inquirer = require('inquirer');

var answers = {
    target  : "www.github.com",
    dev : "en0",
};

var addr = "192.168.25.91";

console.log('using interface: ' + answers.dev + '(' + addr + ')');
var scanner = new addon.Scanner();
var options = {
    "target" :  answers.target, 
    "address":  addr, 
    "dev" :  answers.dev,
    "ports" : [],
    "rate" : 1024
};
scanner.syn(options, function(ports){
    console.log(ports.length);
})