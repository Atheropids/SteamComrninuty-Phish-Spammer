'use strict';

const https = require('https');
const readline = require('readline');
const tough = require('tough-cookie');

/*
 * Settings are here c:
 * Modify them on your purpose.
 */

// Target C&C server domain name.
let spam_target = 'steamcomrninuty.ru';

// Number of connection procedures in parallel.
let parallel_count = 1;

// Debug mode: only one attempt and verbose output. Used for testing if the spam works.
let debug_mode = false;

// Random TCP error count threshold for each parallel member before abortion.
let error_count_threshold = 8;

// Upper limit of the number of spam messages.
let spam_limit = 1000000;

// User-Agent for faking browser connection.
let useragent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.79 Safari/537.36';

/* END SETTINGS SECTION */

/*
 * Runtime variables and functions below. Do not edit unless needed.
 */

// Readline console object.
let reli = null;

// Determine if the spammer should stop after finishing existing connections.
let stopping = false;

// Count of random TCP errors for each member.
let error_count = new Array(parallel_count);

// Pool for fake password.
let mass_char_sets = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

// Pool for fake email addresses.
let top_level_domains = ['com', 'net', 'org', 'edu'];

// Tough-cookie init.
let Cookie = tough.Cookie;

// Cookie cache for each members.
let lumen_sessions = new Array(parallel_count);

// Stage flag for each members.
let spam_stage = new Array(parallel_count);

// Total messages dispatched.
let dispatched_spams = 0;

// Incremental message ID cache for each member.
let spam_sess_idx = new Array(parallel_count);

// Not in debug mode -> start interactive console.
if (!debug_mode) {
  reli = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  reli.on('line', function (line) {
    // If sonsole input is 'stop', flag the process to stop ASAP.
    if (line.toLowerCase() === 'stop') {
      stopping = true;
      reli.close();
    }
  });
}

// Epoch time long int -> byte[].
function time_seed() {
  let rSeed = new Uint8Array(8);
  let rTime = Date.now();
  let i;
  for (i = 0; i < 8; i++) {
    rSeed[i] = rTime % 256;
    rTime /= 256;
  }
  return rSeed;
}

// Generate randomized fake login info.
function generate_fake_credentials() {
  let email = `.${top_level_domains[Math.floor(Math.random() * top_level_domains.length)]}`;

  let int01 = Math.floor(Math.random() * 0x100000000);
  while (int01 > 0) {
    email = `${String.fromCharCode(int01 % 26 + 97)}${email}`;
    int01 = Math.floor(int01 / 26);
  }
  email = `@${email}`;
  int01 = Math.floor(Math.random() * 0x100000000);
  while (int01 > 0) {
    email = `${String.fromCharCode(int01 % 26 + 97)}${email}`;
    int01 = Math.floor(int01 / 26);
  }

  let password = '';
  for (let i = 0; i < 2; i++) {
    let int02 = Math.floor(Math.random() * 0x100000000);
    while (int02 > 0) {
      password = `${String.fromCharCode(mass_char_sets[int02 % mass_char_sets.length])}${password}`;
      int02 = Math.floor(int02 / mass_char_sets.length);
    }
  }

  return `username=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`;
}

// Spam the malicious server with fake credentials.
// Too bad we cannot execute them in public and drain their dirty blood into sewers alive.
function do_spam(idx) {
  if (stopping) {
    return;
  }

  switch (spam_stage[idx]) {
    // Init case, grab a brand new cookie.
    case 0: {
      // Already spammed enough messages.
      if (dispatched_spams >= spam_limit) {
        return;
      }
      spam_sess_idx[idx] = dispatched_spams;
      dispatched_spams++;

      let req1 = https.request(`https://${spam_target}/`, {
        method: 'GET',
        headers: {
          'User-Agent': useragent
        }
      });
      req1.end();
  
      req1.on('response', function (resp1) {
        let buf1 = Buffer.allocUnsafe(0);
  
        resp1.on('data', function (data) {
          buf1 = Buffer.concat([buf1, data]);
        });
  
        resp1.on('end', function () {
          console.log('[%s:%s] GET cookie attempt ; Status Code -> %d', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), resp1.statusCode);
  
          // Grab our target cookie named 'lumen_session'
          let raw_cookies = resp1.headers['set-cookie'];
          for (let i = 0; i < raw_cookies.length; i++) {
            let cookie = Cookie.parse(raw_cookies[i]);
            if (cookie.key === 'lumen_session') {
              console.log('[%s:%s] FOUND lumen_session => %s', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), lumen_sessions[idx] = cookie.value);
              spam_stage[idx] = 1; // Set stage to proceed.
            } else if (debug_mode) {
              console.log(JSON.stringify(cookie));
            }
          }
  
          if (debug_mode) {
            console.log(JSON.stringify(resp1.headers, null, 2));
            console.log(buf1.toString('utf8'));
          }
          
          // Proceed to next stage if not stopping.
          if (!stopping) {
            setImmediate(do_spam, idx);
          }
        });
      });
  
      req1.on('error', function (err1) {
        console.error(((err1 && err1.stack) ? err1.stack : err1));
        if (!stopping && error_count[idx] < error_count_threshold) {
          error_count[idx]++;
          do_spam(idx);
        }
      });

      break;
    }

    // Final stage, send nonsense data to malicious server.
    case 1: {
      let credential = generate_fake_credentials();
      let content = Buffer.from(credential, 'utf8');

      // This is the final stage. Set stopping flag to true under debug mode to stop as intended.
      if (debug_mode) {
        stopping = true;
      }

      // Setup headers.
      let headers1 = {
        'Host': spam_target,
        'User-Agent': useragent,
        'Origin': `https://${spam_target}`,
        'Referer': `https://${spam_target}/home/login`,
        'Content-Length': `${content.length}`,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'X-Requested-With': 'XMLHttpRequest',
        'Cookie': `lumen_session=${lumen_sessions[idx]}`
      };

      if (debug_mode) {
        console.log(JSON.stringify(headers1, null, 2));
      }

      let req1 = https.request(`https://${spam_target}/login/dologin`, {
        method: 'POST',
        headers: headers1
      });
      req1.end(content);
  
      req1.on('response', function (resp1) {
        let buf1 = Buffer.allocUnsafe(0);
  
        resp1.on('data', function (data) {
          buf1 = Buffer.concat([buf1, data]);
        });
  
        resp1.on('end', function () {
          console.log('[%s:%s] Content -> %s (length: %d) ; Status Code -> %d', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), credential, content.length, resp1.statusCode);
          if (debug_mode) {
            console.log(buf1.toString('utf8'));
          } else if (!stopping) {
            // Received 429 Too Many Request, which means the C&C server has blocked this IP address.
            if (resp1.statusCode == 429) {
              console.log('[%s:%s] ALERT: Received error code 429 (Too Many Requests), abort.', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7));
              if (reli) {
                // Close the interactive console or the process will halt and become an useless zombie.
                reli.close();
              }
              return;
            }

            // Reset cached data and stage
            lumen_sessions[idx] = null;
            spam_stage[idx] = 0;

            // Loop
            setImmediate(do_spam, idx);
          }
        });
      });
  
      req1.on('error', function (err1) {
        console.error(((err1 && err1.stack) ? err1.stack : err1));
        if (!stopping && error_count[idx] < error_count_threshold) {
          error_count[idx]++;
          do_spam(idx);
        }
      });

      break;
    }

    // Wrong stage case. Fix the code if this occurs in the console.
    default: {
      console.error('ERROR: Shouldn\'t be here at all!');
    }
  }
}

// Spawn spam members.
for (let i = 0; i < (debug_mode ? 1 : parallel_count); i++) {
  error_count[i] = spam_stage[i] = 0;
  do_spam(i);
}