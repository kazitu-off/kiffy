<?php
/**
 * Kiffy v2 — PHP backend for shared hosting (no Node, no Python, no DB).
 *
 * Upload this file together with index.html / app.html / android.html and a
 * writable ./data directory. The web app auto-detects this backend when the
 * WebSocket endpoint is not available and switches to HTTP long-polling.
 *
 * Requirements: PHP 7.4+, write access to ./data
 * Admin: set KIFFY_ADMIN_PASSWORD below (empty = admin login disabled).
 *
 * Storage (flock-protected JSON files in ./data):
 *   events.jsonl — append-only chat event log, one JSON object per line
 *   state.json   — sessions, bans, id counter
 *
 * Wire protocol: same message shapes as the Python/Rust servers ("t" field),
 * delivered via:
 *   GET  api.php?action=poll&token=..&since=ID   long-poll (up to ~24 s)
 *   POST api.php   {"a":"join"|"msg"|"pm"|...}   actions
 */

const KIFFY_ADMIN_PASSWORD = '';          // <-- set me on hosting
const MAX_TEXT = 16384;
const HISTORY_LIMIT = 100;
const HISTORY_SEND = 30;
const SESSION_TTL = 40;                   // seconds without a poll before expiry (> LONGPOLL_SECONDS)
const LONGPOLL_SECONDS = 24;
const EVENT_FILE_MAX = 1048576;           // rotate the log above 1 MiB

error_reporting(E_ALL & ~E_DEPRECATED);
@set_time_limit(LONGPOLL_SECONDS + 10);

// CORS headers for cross-origin mobile APK and web clients
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

define('DATA_DIR', __DIR__ . '/data');
define('EVENTS_FILE', DATA_DIR . '/events.jsonl');
define('STATE_FILE', DATA_DIR . '/state.json');

function die_json(string $err, int $code = 400) {
    http_response_code($code);
    echo json_encode(['ok' => false, 'err' => $err]);
    exit;
}

function ensure_storage(): void {
    if (!is_dir(DATA_DIR) && !@mkdir(DATA_DIR, 0775, true)) {
        die_json('server: cannot create ./data — make the folder writable', 500);
    }
    if (!is_file(STATE_FILE)) {
        file_put_contents(STATE_FILE, json_encode([
            'next_id' => 1, 'users' => [], 'bans' => [], 'typing' => [], 'rate' => [],
        ]), LOCK_EX);
    }
}

function state(): array {
    $raw = @file_get_contents(STATE_FILE);
    $st = $raw ? json_decode($raw, true) : null;
    if (!is_array($st)) {
        $st = ['next_id' => 1, 'users' => [], 'bans' => [], 'typing' => []];
    }
    foreach (['next_id', 'users', 'bans', 'typing', 'rate'] as $k) {
        if (!array_key_exists($k, $st)) $st[$k] = $k === 'next_id' ? 1 : [];
    }
    return $st;
}

function save_state(array $st): void {
    file_put_contents(STATE_FILE, json_encode($st), LOCK_EX);
}

/** Append one event with a fresh id; returns the event with its id. */
function push_event(array &$st, array $event): array {
    // never trust the stored counter alone: a log written by an older buggy
    // version may hold higher ids, and reused ids are silently skipped by clients
    $st['next_id'] = max($st['next_id'], state()['next_id'], last_event_id() + 1);
    $id = $st['next_id']++;
    $event['id'] = $id;
    $event['ts'] = time();
    @file_put_contents(EVENTS_FILE, json_encode($event, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    rotate_events_if_needed();
    save_state($st);
    return $event;
}

function rotate_events_if_needed(): void {
    clearstatcache(true, EVENTS_FILE);
    if (!is_file(EVENTS_FILE) || filesize(EVENTS_FILE) <= EVENT_FILE_MAX) {
        return;
    }
    $lines = @file(EVENTS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    $keep = array_slice($lines, -200);
    @file_put_contents(EVENTS_FILE, implode("\n", $keep) . "\n", LOCK_EX);
}

/** Broadcast = append; pollers pick it up. */
function broadcast(array &$st, array $event): array {
    return push_event($st, $event);
}

function sys_event(array &$st, string $text): array {
    return broadcast($st, ['t' => 'sys', 'text' => $text]);
}

function expire_sessions(array &$st): void {
    $now = time();
    foreach ($st['users'] as $tok => $u) {
        if ($now - $u['last'] > SESSION_TTL) {
            $name = $u['name'];
            unset($st['users'][$tok]);
            unset($st['typing'][$name]);
            $st['bans'] = array_filter($st['bans'], fn($b) => $b['ip'] !== $u['ip'] || $b['name_only']);
            sys_event($st, $name . ' left (' . count($st['users']) . ' online)');
            broadcast($st, ['t' => 'users', 'users' => users_payload($st)]);
        }
    }
}

function users_payload(array $st): array {
    $out = [];
    foreach ($st['users'] as $u) {
        // sessions are keyed by token — the display name lives inside the record
        $out[] = ['n' => $u['name'], 's' => !empty($u['star']), 'a' => !empty($u['admin'])];
    }
    return $out;
}

function read_events_since(int $since): array {
    if (!is_file(EVENTS_FILE)) return [];
    $lines = @file(EVENTS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    // binary-search-ish: the log is ordered, scan from the end
    $out = [];
    for ($i = max(0, count($lines) - 400); $i < count($lines); $i++) {
        $ev = json_decode($lines[$i], true);
        if (is_array($ev) && isset($ev['id']) && $ev['id'] > $since) {
            $out[] = $ev;
        }
    }
    return $out;
}

function last_event_id(): int {
    if (!is_file(EVENTS_FILE)) return 0;
    $lines = @file(EVENTS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
    for ($i = count($lines) - 1; $i >= 0; $i--) {
        $ev = json_decode($lines[$i], true);
        if (is_array($ev) && isset($ev['id'])) return (int)$ev['id'];
    }
    return 0;
}

/** PMs are point-to-point: strip events this user must not see. */
function filter_events_for(array $events, string $name): array {
    $out = [];
    foreach ($events as $ev) {
        if (($ev['t'] ?? '') === 'pm' && ($ev['from'] ?? '') !== $name && ($ev['to'] ?? '') !== $name) continue;
        $out[] = $ev;
    }
    return $out;
}

function valid_name(string $name): bool {
    return (bool)preg_match('/^[a-zA-Z0-9_]{3,20}$/', $name);
}

function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '?';
}

function rate_ok(array &$st, string $key): bool {
    $now = microtime(true);
    if (!isset($st['rate'][$key])) $st['rate'][$key] = ['tokens' => 30.0, 'ts' => $now];
    $b = &$st['rate'][$key];
    $b['tokens'] = min(30.0, $b['tokens'] + ($now - $b['ts']) * (30.0 / 60.0));
    $b['ts'] = $now;
    if ($b['tokens'] >= 1.0) { $b['tokens'] -= 1.0; return true; }
    return false;
}

ensure_storage();
$st = state();
expire_sessions($st);

$action = $_GET['action'] ?? null;
if ($action === null) {
    $in = json_decode(file_get_contents('php://input') ?: '', true);
    // clients speak the WS wire protocol ("t" field); "a" kept for the PHP-native actions
    $action = is_array($in) ? ($in['a'] ?? ($in['t'] ?? null)) : null;
}

switch ($action) {
    case 'probe':
        echo json_encode(['ok' => true, 'transport' => 'poll', 'v' => 2]);
        exit;

    case 'join': {
        $in = json_decode(file_get_contents('php://input') ?: '', true) ?: [];
        $name = trim((string)($in['user'] ?? ''));
        $ip = client_ip();

        // a page reload can beat the 75 s session expiry: resume own session instead of "taken"
        $resume = (string)($in['resume'] ?? '');
        $inherit = null;
        if ($resume !== '' && isset($st['users'][$resume]) && $st['users'][$resume]['name'] === $name) {
            $inherit = $st['users'][$resume];
            unset($st['users'][$resume]);
            unset($st['typing'][$name]);
        }

        foreach ($st['bans'] as $b) {
            if ($b['name_only'] && $b['ip'] === $name) {
                die_json('You are banned from this server.', 403);
            }
            if (!$b['name_only'] && $b['ip'] === $ip) {
                die_json('You are banned from this server.', 403);
            }
        }
        if (!valid_name($name)) die_json('Invalid username: 3-20 chars, letters/digits/_');
        foreach ($st['users'] as $u) {
            if ($u['name'] === $name) die_json('Username already taken.');
        }

        $admin = false;
        if ($name === 'admin') {
            if (KIFFY_ADMIN_PASSWORD === '') {
                die_json('Admin login is disabled: set KIFFY_ADMIN_PASSWORD in api.php');
            }
            $pw = (string)($in['pw'] ?? '');
            if (!hash_equals(KIFFY_ADMIN_PASSWORD, $pw)) die_json('Wrong admin password.');
            $admin = true;
        }

        $token = bin2hex(random_bytes(16));
        $st['users'][$token] = [
            'name' => $name, 'admin' => $admin || !empty($inherit['admin']), 'star' => !empty($inherit['star']),
            'ip' => $ip, 'last' => time(), 'anchor' => null,
        ];
        save_state($st);

        broadcast($st, ['t' => 'users', 'users' => users_payload($st)]);
        sys_event($st, $name . ' joined (' . count($st['users']) . ' online)');

        $events = read_events_since(max(0, last_event_id() - HISTORY_SEND));
        $since = $events ? end($events)['id'] : last_event_id();
        echo json_encode([
            'ok' => true,
            't' => 'welcome',
            'user' => $name,
            'admin' => $admin,
            'users' => users_payload($st),
            'history' => array_slice(filter_events_for($events, $name), -HISTORY_SEND),
            'since' => $since,
            'token' => $token,
            'psk' => false,
        ]);
        exit;
    }

    case 'poll': {
        $token = (string)($_GET['token'] ?? '');
        if (!isset($st['users'][$token])) die_json('expired', 401);
        $me = &$st['users'][$token];
        $me['last'] = time();
        save_state($st);
        $since = (int)($_GET['since'] ?? 0);

        // long-poll: wait up to LONGPOLL_SECONDS for new events
        $deadline = time() + LONGPOLL_SECONDS;
        $events = read_events_since($since);
        while (empty($events) && time() < $deadline) {
            usleep(400000);
            $events = read_events_since($since);
            if (rand(0, 40) === 0) {           // periodic housekeeping
                $st = state();
                expire_sessions($st);
                if (!isset($st['users'][$token])) die_json('expired', 401);
                $st['users'][$token]['last'] = time();
                save_state($st);
            }
        }
        // no save_state here: the session may have been removed (exit/ban) while we
        // waited, and writing back our stale copy would resurrect it
        $newSince = $events ? end($events)['id'] : $since;
        $who = isset($st['users'][$token]) ? $st['users'][$token]['name'] : '';
        echo json_encode([
            'ok' => true,
            'events' => filter_events_for($events, $who),
            'users' => users_payload($st),
            'since' => $newSince,
        ]);
        exit;
    }

    case 'msg': case 'pm': case 'typing': case 'anchor': case 'unanchor':
    case 'users': case 'ping': case 'exit': {
        $in = json_decode(file_get_contents('php://input') ?: '', true) ?: [];
        $token = (string)($in['token'] ?? '');
        if (!isset($st['users'][$token])) die_json('expired', 401);
        $me = &$st['users'][$token];
        $me['last'] = time();
        $name = $me['name'];

        if ($action === 'ping') {
            save_state($st);
            echo json_encode(['ok' => true, 't' => 'pong', 'ts' => $in['ts'] ?? 0]);
            exit;
        }
        if ($action === 'exit') {
            unset($st['users'][$token]);
            unset($st['typing'][$name]);
            save_state($st);
            sys_event($st, $name . ' left (' . count($st['users']) . ' online)');
            broadcast($st, ['t' => 'users', 'users' => users_payload($st)]);
            echo json_encode(['ok' => true]);
            exit;
        }
        if ($action === 'users') {
            save_state($st);
            echo json_encode(['ok' => true, 'users' => users_payload($st)]);
            exit;
        }
        if ($action === 'typing') {
            $on = !empty($in['on']);
            $changed = false;
            if ($on && !isset($st['typing'][$name])) { $st['typing'][$name] = time() + 5; $changed = true; }
            if (!$on && isset($st['typing'][$name])) { unset($st['typing'][$name]); $changed = true; }
            save_state($st);
            if ($changed) {
                broadcast($st, ['t' => 'typing', 'user' => $name, 'on' => $on]);
            }
            echo json_encode(['ok' => true]);
            exit;
        }
        if ($action === 'anchor') {
            $to = (string)($in['to'] ?? '');
            $found = false;
            foreach ($st['users'] as $u) if ($u['name'] === $to) $found = true;
            if ($found && $to !== $name) {
                $me['anchor'] = $to;
                save_state($st);
                echo json_encode(['ok' => true]);
            } else {
                die_json('User ' . $to . ' not found.');
            }
            exit;
        }
        if ($action === 'unanchor') {
            $me['anchor'] = null;
            save_state($st);
            echo json_encode(['ok' => true]);
            exit;
        }

        // msg / pm are rate limited
        if (!rate_ok($st, $name)) {
            save_state($st);
            broadcast($st, ['t' => 'error', 'msg' => 'Rate limit: max 30 messages per minute.']);
            echo json_encode(['ok' => false, 'err' => 'Rate limit: max 30 messages per minute.']);
            exit;
        }

        $text = trim((string)($in['text'] ?? ''));
        // some hostings ship PHP without the mbstring extension
        $text = function_exists('mb_substr') ? mb_substr($text, 0, MAX_TEXT) : substr($text, 0, MAX_TEXT);

        if ($action === 'pm') {
            $to = trim((string)($in['to'] ?? ''));
            if ($to === '' && !empty($me['anchor'])) $to = $me['anchor'];
            if ($text === '') { echo json_encode(['ok' => true]); exit; }
            $found = false;
            foreach ($st['users'] as $u) if ($u['name'] === $to) $found = true;
            if ($found) {
                broadcast($st, ['t' => 'pm', 'from' => $name, 'to' => $to, 'text' => $text]);
                echo json_encode(['ok' => true]);
            } else {
                echo json_encode(['ok' => false, 'err' => 'User ' . $to . ' is not online.']);
            }
            exit;
        }

        // public message or slash command
        if ($text !== '' && $text[0] === '/') {
            $parts = explode(' ', $text, 2);
            $cmd = strtolower($parts[0]);
            $rest = trim($parts[1] ?? '');
            $isAdmin = !empty($me['admin']) || $name === 'admin';
            save_state($st);

            if ($cmd === '/exit') {
                unset($st['users'][$token]);
                unset($st['typing'][$name]);
                save_state($st);
                sys_event($st, $name . ' left (' . count($st['users']) . ' online)');
                broadcast($st, ['t' => 'users', 'users' => users_payload($st)]);
                echo json_encode(['ok' => true]); exit;
            }
            if ($cmd === '/help') {
                broadcast($st, ['t' => 'sys', 'text' => 'Commands: /users /s [user] [msg] /anchor [user] /unanchor']);
                echo json_encode(['ok' => true]); exit;
            }
            if ($cmd === '/users') {
                broadcast($st, ['t' => 'users', 'users' => users_payload($st)]);
                echo json_encode(['ok' => true]); exit;
            }
            if ($cmd === '/s') {
                $pp = explode(' ', $rest, 2);
                $to = trim($pp[0] ?? ''); $body = trim($pp[1] ?? '');
                $found = false;
                foreach ($st['users'] as $u) if ($u['name'] === $to) $found = true;
                if ($found && $body !== '') {
                    broadcast($st, ['t' => 'pm', 'from' => $name, 'to' => $to, 'text' => $body]);
                    echo json_encode(['ok' => true]);
                } else {
                    echo json_encode(['ok' => false, 'err' => 'User ' . $to . ' is not online.']);
                }
                exit;
            }
            if ($cmd === '/anchor') {
                $me['anchor'] = $rest; save_state($st);
                echo json_encode(['ok' => true]); exit;
            }
            if ($cmd === '/unanchor') {
                $me['anchor'] = null; save_state($st);
                echo json_encode(['ok' => true]); exit;
            }
            if ($isAdmin && $cmd === '/global' && $rest !== '') {
                broadcast($st, ['t' => 'global', 'from' => $name, 'text' => $rest]);
                echo json_encode(['ok' => true]); exit;
            }
            if ($isAdmin && $cmd === '/star') {
                foreach ($st['users'] as $tk => $u) {
                    if ($u['name'] === $rest) { $st['users'][$tk]['star'] = true; }
                }
                save_state($st);
                sys_event($st, '⭐ ' . $rest . ' received the Kiffy Star');
                echo json_encode(['ok' => true]); exit;
            }
            if ($isAdmin && $cmd === '/unstar') {
                foreach ($st['users'] as $tk => $u) {
                    if ($u['name'] === $rest) { $st['users'][$tk]['star'] = false; }
                }
                save_state($st);
                echo json_encode(['ok' => true]); exit;
            }
            if ($isAdmin && $cmd === '/ban') {
                $bp = explode(' ', $rest, 2);
                $target = $bp[0]; $reason = trim($bp[1] ?? '') ?: 'No reason';
                if ($target === 'admin') { echo json_encode(['ok' => false, 'err' => 'Cannot ban the main admin.']); exit; }
                $victimToken = null; $victimIp = null;
                foreach ($st['users'] as $tk => $u) {
                    if ($u['name'] === $target) { $victimToken = $tk; $victimIp = $u['ip']; }
                }
                if ($victimToken !== null) {
                    broadcast($st, ['t' => 'sys', 'text' => 'You are banned. Reason: ' . $reason]);
                    unset($st['users'][$victimToken]);
                    unset($st['typing'][$target]);
                    // keep a name ban for a day (name-only marker; IP bans are unsafe on shared hosting NAT)
                    $st['bans'][$target] = ['ip' => $target, 'name_only' => true];
                    save_state($st);
                    sys_event($st, $target . ' was banned (reason: ' . $reason . ')');
                    broadcast($st, ['t' => 'users', 'users' => users_payload($st)]);
                    echo json_encode(['ok' => true]); exit;
                }
                echo json_encode(['ok' => false, 'err' => 'User ' . $target . ' not found.']); exit;
            }
            if ($isAdmin && $cmd === '/unban') {
                unset($st['bans'][$rest]); save_state($st);
                broadcast($st, ['t' => 'sys', 'text' => $rest . ' unbanned.']);
                echo json_encode(['ok' => true]); exit;
            }
            echo json_encode(['ok' => false, 'err' => 'Unknown command. Try /help']); exit;
        }

        if ($text !== '') {
            $star = !empty($me['star']);
            broadcast($st, ['t' => 'msg', 'from' => $name, 'text' => $text, 'star' => $star]);
            unset($st['typing'][$name]);
            save_state($st);
            echo json_encode(['ok' => true]);
        } else {
            echo json_encode(['ok' => true]);
        }
        exit;
    }

    default:
        die_json('unknown action');
}
