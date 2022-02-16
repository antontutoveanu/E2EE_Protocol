// imports
const { performance } = require('perf_hooks');
const fs = require('fs');
const crypto = require('crypto')

//========================================================================================//
// CLIENT SIDE PROTOCOL TEST 3
//========================================================================================//
// STEP 4: DECRYPT ENC_MK WITH SESSION_KEY
//========================================================================================//
// open server_enc_mk.txt and read into array
var ENC_MASTER_KEY_base64_array = [];
var text = fs.readFileSync("../data/server_enc_mk.txt").toString();
var ENC_MASTER_KEY_base64_array = text.split("\n");

// open client_ss.txt and read into array
var ss_base64_array = [];
var text = fs.readFileSync("../data/client_ss.txt").toString();
var ss_base64_array = text.split("\n");

var MASTER_KEY_base64_array = [];
var time_sum4 = 0;
for (var i=0; i<100; i++){ // average of 100 test runs

    // keep in base64 string form
    var ENC_MASTER_KEY_base64 = ENC_MASTER_KEY_base64_array[i];

    // get session key (in base64 string)
    var SESSION_KEY_base64 = ss_base64_array[i];

    // start timer
    var start = performance.now();
    
    //-------------------------------------------------------
    // 4. Decrypt ENC_MASTER_KEY with SESSION_KEY
    var MASTER_KEY_base64 = AES256GCM_DECRYPT(SESSION_KEY_base64, ENC_MASTER_KEY_base64);
    //-------------------------------------------------------

    // end timer
    var end = performance.now();

    // append to array
    MASTER_KEY_base64_array[i] = MASTER_KEY_base64;

    // add to time sum
    var time4 = end - start;
    time_sum4 += time4 * 100; // convert to microseconds
}
// calculate average time for step 4
var avg_time4 = time_sum4/100;
console.log("Average time step 4: ", avg_time4, " microseconds");
// check all keys in the array are the same
var MASTER_KEY_base64;
for(var i=0; i<100; i++){
    var MASTER_KEY_base64 = MASTER_KEY_base64_array[0];
    if(MASTER_KEY_base64 != MASTER_KEY_base64_array[i]){
        console.log("Error in decrypting master keys: not all keys the same.");
    }
}
//========================================================================================//
// STEP 5: DECRYPT ENC_DATA WITH MASTER_KEY
//========================================================================================//
// read in encrypted text file : ciphertext.txt
var ENC_DATA_base64 = fs.readFileSync("../data/ciphertext.txt").toString();
var DATA;
var time_sum5 = 0;
for (var i=0; i<100; i++){ // average of 100 test runs

    // start timer
    var start = performance.now();

    //-------------------------------------------------------
    // 5. Decrypt email data with MASTER_KEY
    var DATA_base64 = AES256GCM_DECRYPT(MASTER_KEY_base64, ENC_DATA_base64);
    // decode from base64 to utf8 string
    DATA = new Buffer.from(DATA_base64, 'base64').toString('utf8');
    //-------------------------------------------------------

    // end timer
    var end = performance.now();

    // add to time sum
    var time5 = end - start;
    time_sum5 += time5 * 100; // convert to microseconds
}
// calculate average time for step 4
var avg_time5 = time_sum5/100;
console.log("Average time step 5: ", avg_time5, " microseconds");

// print first 200 characters of decrypted data to show it works
console.log(DATA.slice(0,200));


// KEY and CIPHERTEXT are base64 strings
function AES256GCM_DECRYPT(KEY, CIPHERTEXT) {

    const key = Buffer.from(KEY, 'base64');
    const ivLength = 12;
    const tagLength = 16;

    function decode(CIPHERTEXT) {
        const inputBuffer = Buffer.from(CIPHERTEXT, 'base64');
        const iv = Buffer.allocUnsafe(ivLength);
        const tag = Buffer.allocUnsafe(tagLength);
        const data = Buffer.alloc(inputBuffer.length - ivLength - tagLength, 0);

        inputBuffer.copy(iv, 0, 0, ivLength);
        inputBuffer.copy(tag, 0, inputBuffer.length - tagLength);
        inputBuffer.copy(data, 0, ivLength);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
        
        decipher.setAuthTag(tag);
        
        let dec = decipher.update(data, 'base64', 'base64');
        dec += decipher.final('base64');
        return dec;
    }
    const PLAINTEXT = decode(CIPHERTEXT);

    // output is base64 string
	return PLAINTEXT;
}

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