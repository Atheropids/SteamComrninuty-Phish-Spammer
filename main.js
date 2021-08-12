/*
 * Copyright (c) 2021, Atheropids. All rights reserved.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

'use strict';

const https = require('https');
const readline = require('readline');
const tough = require('tough-cookie');

// Spec holder class. Please see comments of member variables for details.
class PhishingServer {
  constructor(__domain, __entry_path = '/', __login_page = '/home/login', __login_inbox = '/login/dologin') {

    // Target C&C server domain name.
    this.target_domain = __domain;

    // Remote path for server cookie init.
    this.entry_path = __entry_path;

    // Remote path of the phishing page.
    this.phishing_page_path = __login_page;

    // Remote path of the phishing data receiver.
    this.phishing_target_path = __login_inbox;
  }
}

/*
 * Settings are here c:
 * Modify them on your purpose.
 */

// List of malicious servers.
let spam_targets = [
  // [seized operation] new PhishingServer('steamcomrninuty.ru'),
  // [seized operation] new PhishingServer('steamcommnunmity.com', '/id/zxayonax'),
  // [seized operation] new PhishingServer('nitro-discord.ru', '/airdrop'),
  new PhishingServer('steamcommunity.link'),
  new PhishingServer('discorcl.link'),
  new PhishingServer('steamcommmunilty.com', '/tradoffer/new/?partner=406482431&token=lfk938iK'),
];

// Debug mode: only one attempt and verbose output. Used for testing if the spam works.
let debug_mode = false;

// Number of connection procedures in parallel.
let parallel_count = 4;

// Random TCP error count threshold for each parallel member before abortion.
let error_count_threshold = 8;

// Upper limit of the number of spam messages.
let spam_limit = 1000;

// Determine if the process should continue after receiving HTTP 429 (Too Many Requests).
//  If this is set to a positive value (in seconds), the process will sleep for the spicified time before restart spamming;
//  Else, the process terminates after receiving HTTP 429.
let sleep_when_429 = 600;

// When sleep_when_429 is set and all servers are returning HTTP 429 errors, the target pool may be empty for a while.
//  The members will constantly check if the target pool has become available again with this interval in milliseconds.
let revive_interval = 250;

// User-Agent for faking browser connection.
let useragent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.79 Safari/537.36';

/* END SETTINGS SECTION */

/*
 * Runtime variables and functions below. Do not edit unless needed.
 */

// Target pool. Used to deal with sleeping functionality for HTTP 429.
let target_pool = new Map();
for(let i = 0 ; i < spam_targets.length ; i++) {
  spam_targets[i].index = i;
  target_pool.set(spam_targets[i].target_domain, spam_targets[i]);
}

// Sleep timeout handler objects.
let timeout_handles_targets = new Array(spam_targets.length);

// Readline console object.
let reli = null;

// Determine if the spammer should stop after finishing existing connections.
let stopping = false;

// Count of random TCP errors for each member.
let error_count = new Array(parallel_count);

// Pool for fake password.
let mass_char_sets = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_____');

// Tough-cookie init.
let Cookie = tough.Cookie;

// Parallel spam members alive
let spam_members_alive = parallel_count;

// Cookie cache for each members.
let lumen_sessions = new Array(parallel_count);

// Another cookie cache for each members. It is used occationally.
let _tdg = new Array(parallel_count);

// Stage flag for each members.
let spam_stage = new Array(parallel_count);

// Total messages dispatched.
let dispatched_spams = 0;

// Incremental message ID cache for each member.
let spam_sess_idx = new Array(parallel_count);

// Sleep timeout handler objects.
let timeout_handles_member = new Array(parallel_count);

// Cached targets for each session.
let spam_targets_cache = new Array(parallel_count);

function randomU32() {
  return Math.floor(Math.random() * 0x100000000);
}

// Generate a random string as fake username or password.
function generate_random_string() {
  let ret = '';
  for (let i = 0; i < 2; i++) {
    let int01 = randomU32();
    while (int01 > 0) {
      ret = `${String.fromCharCode(mass_char_sets[int01 % mass_char_sets.length])}${ret}`;
      int01 = Math.floor(int01 / mass_char_sets.length);
    }
  }
  return ret;
}

// Generate randomized fake login info.
function generate_fake_credentials() {
  return `username=${encodeURIComponent(generate_random_string())}&password=${encodeURIComponent(generate_random_string())}`;
}

// Remove a parallel member when needed
function kill_spam_member()
{
  spam_members_alive--;

  // No member is alive, close the console to avoid zombifying
  if(spam_members_alive <= 0) {
    reli.close();
    for (let i = 0 ; i < spam_targets.length ; i++) {
      if (timeout_handles_targets[i]) {
        clearTimeout(timeout_handles_targets[i]);
        timeout_handles_targets[i] = null;
      }
    }
  }
}

// Spam the malicious server with fake credentials.
// Too bad we cannot execute them in public and drain their dirty blood into sewers alive.
function do_spam(idx) {
  if (stopping) {
    kill_spam_member();
    return;
  }

  switch (spam_stage[idx]) {
    // Init case, grab a brand new cookie.
    case 0: {
      // Already spammed enough messages.
      if (dispatched_spams >= spam_limit) {
        kill_spam_member();
        return;
      }

      // Check targets availibility
      if (target_pool.size > 0) {
        timeout_handles_member[idx] = null;
        spam_targets_cache[idx] = target_pool.get(Array.from(target_pool.keys())[randomU32() % target_pool.size]);
      } else {
        if (sleep_when_429 > 0) {
          timeout_handles_member[idx] = setTimeout(do_spam, revive_interval, idx);
        } else {
          stopping = true;
          kill_spam_member();
        }
        return;
      }

      spam_sess_idx[idx] = dispatched_spams;
      dispatched_spams++;

      let req1 = https.request(`https://${spam_targets_cache[idx].target_domain}${spam_targets_cache[idx].entry_path}`, {
        method: 'GET',
        headers: {
          'User-Agent': useragent
        }
      });
      req1.end();

      console.log('[%s:%s] Target: %s', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), spam_targets_cache[idx].target_domain);

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
              spam_stage[idx] = (resp1.statusCode === 200 ? 3 : 2); // Set stage to proceed.
            } else if (cookie.key.toLowerCase() === '_tdg' && !_tdg[idx]) {
              console.log('[%s:%s] FOUND _tdg => %s', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), _tdg[idx] = cookie.value);
              // lumen_session not present but _tdg -s available -> need to get lumen_session using _tdg first. 
              if(spam_stage[idx] < 2) {
                spam_stage[idx] = 1;
              }
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
          } else {
            kill_spam_member();
          }
        });
      });

      req1.on('error', function (err1) {
        console.error(((err1 && err1.stack) ? err1.stack : err1));
        if (!stopping && error_count[idx] < error_count_threshold) {
          error_count[idx]++;
          setImmediate(do_spam, idx);
        } else {
          kill_spam_member();
        }
      });

      break;
    }

    // Intermediate stage, where _tdg is present but not lumen_session.
    case 1: {
      let req1 = https.request(`https://${spam_targets_cache[idx].target_domain}${spam_targets_cache[idx].entry_path}`, {
        method: 'GET',
        headers: {
          'User-Agent': useragent,
          'Cookie': `_tdg=${_tdg[idx]}; _TDG=${_tdg[idx]}`
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
              spam_stage[idx] = (resp1.statusCode === 200 ? 3 : 2); // Set stage to proceed.
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
          } else {
            kill_spam_member();
          }
        });
      });

      req1.on('error', function (err1) {
        console.error(((err1 && err1.stack) ? err1.stack : err1));
        if (!stopping && error_count[idx] < error_count_threshold) {
          error_count[idx]++;
          setImmediate(do_spam, idx);
        } else {
          kill_spam_member();
        }
      });

      break;
    }


    // Intermediate stage, where a 200 OK is required before shooting.
    case 2: {
      let cookie = `lumen_session=${lumen_sessions[idx]}`;
      if (_tdg[idx]) {
        cookie = `_tdg=${_tdg[idx]}; ${cookie}; _TDG=${_tdg[idx]}`;
      }
      let req1 = https.request(`https://${spam_targets_cache[idx].target_domain}${spam_targets_cache[idx].entry_path}`, {
        method: 'GET',
        headers: {
          'User-Agent': useragent,
          'Cookie': cookie
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
            if (cookie.key.toLowerCase() === '_tdg' && !_tdg[idx]) {
              console.log('[%s:%s] FOUND _tdg => %s', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), _tdg[idx] = cookie.value);
            }
          }

          if (resp1.statusCode === 200) {
            spam_stage[idx] = 3;
          }

          if (debug_mode) {
            console.log(JSON.stringify(resp1.headers, null, 2));
            console.log(buf1.toString('utf8'));
          }

          // Proceed to next stage if not stopping.
          if (!stopping) {
            setImmediate(do_spam, idx);
          } else {
            kill_spam_member();
          }
        });
      });

      req1.on('error', function (err1) {
        console.error(((err1 && err1.stack) ? err1.stack : err1));
        if (!stopping && error_count[idx] < error_count_threshold) {
          error_count[idx]++;
          setImmediate(do_spam, idx);
        } else {
          kill_spam_member();
        }
      });

      break;
    }

    // Final stage, send nonsense data to malicious server.
    case 3: {
      let credential = generate_fake_credentials();
      let content = Buffer.from(credential, 'utf8');

      // This is the final stage. Set stopping flag to true under debug mode to stop as intended.
      if (debug_mode) {
        stopping = true;
      }

      // Setup headers.
      let cookie = `lumen_session=${lumen_sessions[idx]}`;
      if (_tdg[idx]) {
        cookie = `_tdg=${_tdg[idx]}; ${cookie}; _TDG=${_tdg[idx]}`;
      }
      let headers1 = {
        'Host': spam_targets_cache[idx].target_domain,
        'User-Agent': useragent,
        'Connection': 'keep-alive',
        'Origin': `https://${spam_targets_cache[idx].target_domain}`,
        'Referer': `https://${spam_targets_cache[idx].target_domain}${spam_targets_cache[idx].phishing_page_path}`,
        'Content-Length': `${content.length}`,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'DNT': '1',
        'X-Requested-With': 'XMLHttpRequest',
        'Cookie': cookie
      };

      if (debug_mode) {
        console.log(JSON.stringify(headers1, null, 2));
      }

      let req1 = https.request(`https://${spam_targets_cache[idx].target_domain}${spam_targets_cache[idx].phishing_target_path}`, {
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
          let resp_content = buf1.toString('utf8');
          if (debug_mode) {
            console.log(resp1.headers);
            console.log(resp_content);
          }
          
          // Received 429 Too Many Request, which means the C&C server has temporarily blocked this IP address.
          if (resp1.statusCode === 429) {
            if (sleep_when_429 > 0) {
              console.log('[%s:%s] ALERT: Received error code 429 (Too Many Requests), mute %s for %s seconds.', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), spam_targets_cache[idx].target_domain, sleep_when_429.toFixed(2));

              // Put the server into hibernation mode.
              if (target_pool.has(spam_targets_cache[idx].target_domain)) {
                target_pool.delete(spam_targets_cache[idx].target_domain);
                timeout_handles_targets[spam_targets_cache[idx].index] = setTimeout((server_entry) => {
                  target_pool.set(server_entry.target_domain, server_entry);
                }, sleep_when_429 * 1000, spam_targets_cache[idx]);
              }
            } else {
              console.log('[%s:%s] ALERT: Received error code 429 (Too Many Requests), abort.', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7));

              if (target_pool.has(spam_targets_cache[idx].target_domain)) {
                target_pool.delete(spam_targets_cache[idx].target_domain);
              }

              if (target_pool.size <= 0) {
                stopping = true;
                kill_spam_member();
                return;
              }
            }
          } else if (resp1.statusCode === 200) {
            let content_type = resp1.headers['content-type'] || resp1.headers['Content-Type'];
            if (content_type === 'application/json') {
              let json_content = null;
              try {
                json_content = JSON.parse(resp_content);
              } catch (err) {
                console.error('Server returned malformed JSON!');
                console.error(err.stack);
              }
              if (json_content) {
                console.log('[%s:%s] Message: %s %s', `0${idx}`.slice(-2), `000000${spam_sess_idx[idx]}`.slice(-7), json_content['message'], json_content['code'] === 0 ? '(GOOD)' : '(Unexpected)');
              }
            }
          }
          
          if (!stopping) {
            // Reset cached data and stage
            lumen_sessions[idx] = null;
            _tdg[idx] = null;
            spam_stage[idx] = 0;

            // Loop
            setImmediate(do_spam, idx);
          } else {
            kill_spam_member();
          }
        });
      });

      req1.on('error', function (err1) {
        console.error(((err1 && err1.stack) ? err1.stack : err1));
        if (!stopping && error_count[idx] < error_count_threshold) {
          error_count[idx]++;
          setImmediate(do_spam, idx);
        } else {
          kill_spam_member()
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

console.log('---->> Anti-Phish Fake Credential Spammer by Atheropids <<----');

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

      // Clear sleeping members;
      for (let i = 0 ; i < parallel_count ; i++) {
        if (timeout_handles_member[i]) {
          clearTimeout(timeout_handles_member[i]);
          timeout_handles_member[i] = null;
          kill_spam_member();
        }
      }
    }
  });
}

// Spawn spam members.
for (let i = 0; i < (debug_mode ? 1 : parallel_count); i++) {
  error_count[i] = spam_stage[i] = 0;
  do_spam(i);
}
