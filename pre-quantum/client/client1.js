// imports
const { performance } = require('perf_hooks');
const fs = require('fs');
const rsa = require('trsa');
const generator = require('./rand');

// server's hardcoded RSA public key
const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\n' +
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAj0e0gFqwocqu0ulq0BUV\n' +
'HaMTVgEP1wy0aNeFjTM0vm+BkDlzjfIyNRwckF+sF9+moMvei2uyl08doOsq1R39\n' +
'4MfQCvnwuj23O048xz1O+enE/MGcLvfwW5kKyd3mzv9jmK1ZhoeVH1yh0AKsios7\n' +
'Sa306vZqRjTorpAoBlijM3E5dpMydl+CNBDONXOp94WaGX61Thpi2XIU/iGalLIP\n' +
'E53lMvIA674D7OzA4L0esnCZvxhgbtL3kH3dsq32Tf293lbLDFYl210gPTqaxQE8\n' +
'0f0imxGNYIYxN52HZuH8OQ02WCavrkc+WZYXioOUsp2Q3WOj2vykKeQfoIH8+9qk\n' +
'MQIDAQAB\n' +
'-----END PUBLIC KEY-----';

//========================================================================================//
// CLIENT SIDE PROTOCOL TEST 1
//========================================================================================//
// STEP 1: SESSION KEY ENCAPSULATION
//========================================================================================//
var time_sum1 = 0;
var c_hex_array = [];
var ss_base64_array = [];
for (var i=0; i<100; i++){ // average of 100 test runs

    // generate random 32 byte key
    var ss = rndSessionKey();

    // start timer
    var start = performance.now();

    //-------------------------------------------------------
    // encode session key to utf8 string
    var ss_str = new Buffer.from(ss).toString('base64');
    // 1. Encrypt session key with RSA
    var c_hex = rsa.encrypt(ss_str, PUBLIC_KEY);
    //-------------------------------------------------------

    // end timer
    var end = performance.now();

    // add to time sum
    var time1 = end - start;
    time_sum1 += time1 * 100; // convert to microseconds

    // add c and ss to arrays
    c_hex_array[i] = c_hex;
    var ss_base64 = new Buffer.from(ss).toString('base64');
    ss_base64_array[i] = ss_base64;
}
// calculate average time for step 1
var avg_time1 = time_sum1/100;
console.log("Average time step 1: ", avg_time1, " microseconds");

// add ss and c values to text file (for server side testing)
// clear files first
fs.writeFile('../data/client_c.txt', '', (err) => { if (err) throw err; });
fs.writeFile('../data/client_ss.txt', '', (err) => { if (err) throw err; });
for ( var i=0; i<100; i++){
    // write values to file
    fs.appendFileSync('../data/client_c.txt', c_hex_array[i], (err) => { if (err) throw err; });
    fs.appendFileSync('../data/client_c.txt', "\n", (err) => { if (err) throw err; });
}
for ( var i=0; i<100; i++){
    // write values to file
    fs.appendFileSync('../data/client_ss.txt', ss_base64_array[i], (err) => { if (err) throw err; });
    fs.appendFileSync('../data/client_ss.txt', "\n", (err) => { if (err) throw err; });
}
//========================================================================================//
//========================================================================================//

// send c to server

//========================================================================================//


function toBASE64(bytes){
    var string = new Buffer.from(bytes).toString('base64');
    return string;
}

function fromBASE64(string){
    var bytes = [];
    var buffer = new Buffer.from(string, 'base64');
    for (var i=0; i<buffer.length; i++){
        bytes[i] = buffer[i];
    }
    return bytes;
}

function rndSessionKey(){
    // read 32 random values (0-255) into a 32 byte array
    let rnd = new Array(32);
    for (let i = 0; i < 32; i++) {
        rnd[i] = generator.nextInt(256);
    }
    return rnd;
}