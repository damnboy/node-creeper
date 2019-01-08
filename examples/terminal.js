const addon = require('../build/Debug/node-creeper-native');
var inquirer = require('inquirer');
var pcapDev = new addon.PcapDevice();
pcapDev.listDevice(function(interfaces){
    inquirer
    .prompt([
        {
            type: 'list',
            choices : Object.keys(interfaces),
            default : Object.keys(interfaces)[0],
            name : 'dev',
            message : 'network interfaces'
        },
        {
            name : 'target',
            message : 'target host'
        }
    ])
    .then(answers => {
        // Use user feedback for... whatever!!
        var addr = interfaces[answers.dev].pop()
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
    });
});
