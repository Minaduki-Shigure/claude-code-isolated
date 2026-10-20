#!/usr/bin/env python3
"""Bounded current-frame native-footer observer. No terminal transcript retained."""
import codecs
import errno
import fcntl
import os
import re
import select
import signal
import struct
import subprocess
import termios
import time
import tty
import unicodedata

import pyte


class AnsiGuard:
    """Discard string controls and bound CSI before feeding a private screen."""
    def __init__(self):
        self.state = 'text'
        self.pending = ''
        self.combining = 0
        self.string_kind = ''

    def feed(self, data):
        out = []
        for char in data:
            if self.state == 'string':
                if char == '\x9c' or (char == '\x07' and self.string_kind == 'osc'):
                    self.state = 'text'
                elif char == '\x1b': self.state = 'string-esc'
                continue
            if self.state == 'string-esc':
                if char in ('\\', '\x9c'): self.state = 'text'
                elif char != '\x1b': self.state = 'string'
                continue
            # CAN/SUB cancel an incomplete escape. ESC always starts a fresh one.
            if char in ('\x18', '\x1a'):
                self.state = 'text'; self.pending = ''; continue
            if char == '\x1b':
                self.state = 'esc'; self.pending = ''; continue
            if self.state == 'csi-drop':
                if '@' <= char <= '~': self.state = 'text'
                continue
            if self.state == 'csi':
                if char in '0123456789;' or (char == '?' and self.pending == '\x1b['):
                    self.pending += char
                    if len(self.pending) > 128 or self.pending.count(';') > 24 or re.search(r'\d{7}', self.pending):
                        self.pending = ''; self.state = 'csi-drop'
                elif '@' <= char <= '~':
                    # Reconstruct only the CSI grammar understood by pyte.
                    if char in pyte.Stream.csi:
                        limit = 4096 if char in 'hlm' else 500
                        safe = re.sub(r'\d+', lambda m: str(min(int(m.group()), limit)), self.pending)
                        out.append(safe + char)
                    self.pending = ''; self.state = 'text'
                else:
                    self.pending = ''; self.state = 'csi-drop'
                continue
            if self.state == 'esc':
                if char == '[':
                    self.pending = '\x1b['; self.state = 'csi'
                elif char in ']P^_X':
                    self.string_kind = 'osc' if char == ']' else 'other'
                    self.state = 'string'
                elif char in '()#':
                    self.pending = '\x1b' + char; self.state = 'esc-tail'
                else:
                    if char in pyte.Stream.escape: out.append('\x1b' + char)
                    self.state = 'text'
                continue
            if self.state == 'esc-tail':
                if char in '0AB8': out.append(self.pending + char)
                self.pending = ''; self.state = 'text'; continue
            if '\x80' <= char <= '\x9f':
                if char in '\x90\x98\x9d\x9e\x9f':
                    self.string_kind = 'osc' if char == '\x9d' else 'other'
                    self.state = 'string'
                elif char == '\x9b':
                    self.pending = '\x1b['; self.state = 'csi'
                continue
            if unicodedata.combining(char):
                self.combining += 1
                if self.combining > 4: continue
            elif char.isprintable(): self.combining = 0
            out.append(char)
        return ''.join(out)


class BoundedScreen(pyte.Screen):
    def set_mode(self, *modes, **kwargs):
        allowed = {3, 5, 6, 7, 25} if kwargs.get('private') else {4, 20}
        super().set_mode(*(value for value in modes if value in allowed), **kwargs)

    def reset_mode(self, *modes, **kwargs):
        allowed = {3, 5, 6, 7, 25} if kwargs.get('private') else {4, 20}
        super().reset_mode(*(value for value in modes if value in allowed), **kwargs)

    def save_cursor(self):
        if len(self.savepoints) >= 4: self.savepoints.pop(0)
        super().save_cursor()

    def draw(self, data):
        super().draw(data)
        if not any(unicodedata.combining(char) for char in data): return
        # Combining sequences can revisit a cell through cursor escapes.
        for row in self.buffer.values():
            for column, cell in tuple(row.items()):
                if len(cell.data) > 8:
                    row[column] = cell._replace(data=cell.data[:8])


def extract_footer(screen):
    """Require native input separators and a complete explicit footer label."""
    rows = screen.display
    dividers = [i for i, row in enumerate(rows)
                if row.count('─') >= max(20, screen.columns // 2)]
    pairs = [(upper, lower) for upper, lower in zip(dividers, dividers[1:])
             if 1 < lower - upper < 8 and any(
                 re.match(r'^\s*❯(?:\s|$)', row) for row in rows[upper + 1:lower])]
    if not pairs: return {}
    upper, lower = pairs[-1]
    # Only the last input region with no later non-footer panel can qualify.
    footer = rows[lower + 1:lower + 4]
    if any(row.strip() for row in rows[lower + 4:]): return {}
    mapping = {'manual': 'default', 'auto': 'auto', 'accept edits': 'acceptEdits',
               'plan': 'plan', "don't ask": 'dontAsk', 'dontAsk': 'dontAsk'}
    result = {}
    observed_modes = set()
    for line in footer:
        match = re.fullmatch(r'\s*[⏸⏵▶▷◉●✻]*\s*(manual|auto|accept edits|plan|don\x27t ask|dontAsk)(?: mode)? on(?:\s+\(shift\+tab to cycle\))?\s*', line)
        if match:
            observed_modes.add(mapping[match.group(1)])
    if len(observed_modes) == 1:
        result['permissionMode'] = observed_modes.pop()
    # The complete /effort suffix is required; a missing badge alone says nothing.
    for line in rows[max(0, upper - 2):upper]:
        match = re.fullmatch(r'\s*[◈◇◆○●◉◎◌]\s+(?:low|medium|high|xhigh|max)(?:\s+·\s+(ultracode))?\s+·\s+/effort\s*', line)
        if match:
            result['ultracode'] = bool(match.group(1))
            break
    return result


class FooterObserver:
    def __init__(self, columns, rows, on_change):
        self.on_change = on_change
        self.known = {}
        self.disabled = False
        self.resize(columns, rows)

    def resize(self, columns, rows):
        self.valid_size = 60 <= columns <= 500 and 10 <= rows <= 200
        self.screen = BoundedScreen(min(max(columns, 60), 500), min(max(rows, 10), 200))
        self.stream = pyte.Stream(self.screen)
        self.guard = AnsiGuard()
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')

    def feed(self, data):
        if self.disabled or not self.valid_size: return
        try:
            self.stream.feed(self.guard.feed(self.decoder.decode(data)))
        except Exception:
            self.disabled = True

    def sample(self):
        if self.disabled or not self.valid_size: return
        try:
            fresh = extract_footer(self.screen)
            changed = {k: v for k, v in fresh.items() if self.known.get(k) != v}
            if changed:
                self.on_change(changed)
                self.known.update(changed)
        except Exception:
            self.disabled = True


def run_pty(argv, on_change, env=None):
    """Relay a controlling PTY with bounded queues; observation is best-effort."""
    if not (os.isatty(0) and os.isatty(1)):
        code = subprocess.call(argv, env=env)
        return code if code >= 0 else 128 - code
    original = termios.tcgetattr(0)
    winsize = fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8))
    rows, columns, _, _ = struct.unpack('HHHH', winsize)
    try:
        observer = FooterObserver(columns, rows, on_change)
    except Exception:
        code = subprocess.call(argv, env=env)
        return code if code >= 0 else 128 - code
    master, slave = os.openpty()
    child = None
    prior_signals = {}
    prior_flags = {}
    resize_pending = False
    signal_pending = []
    max_queue = 131072

    def receive_signal(signum, _frame):
        nonlocal resize_pending
        if signum == signal.SIGWINCH:
            resize_pending = True
        elif len(signal_pending) < 16:
            signal_pending.append(signum)

    def signal_child(signum):
        try: os.killpg(child.pid, signum)
        except ProcessLookupError: pass

    try:
        fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize)
        child = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                 start_new_session=True, close_fds=True, env=env,
                                 preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(slave)
        slave = None
        for number in (signal.SIGWINCH, signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            prior_signals[number] = signal.signal(number, receive_signal)
        # Capture all flags before changing descriptors which may share an OFD.
        prior_flags = {fd: fcntl.fcntl(fd, fcntl.F_GETFL) for fd in (0, 1, master)}
        tty.setraw(0)
        for fd, flags in prior_flags.items():
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        input_queue = bytearray()
        output_queue = bytearray()
        active_stdin = True
        active_master = True
        last_output = time.monotonic()
        dirty = False
        exit_deadline = None
        while active_master or output_queue:
            if child.poll() is not None:
                if exit_deadline is None: exit_deadline = time.monotonic() + 1.0
                elif time.monotonic() >= exit_deadline:
                    # Stop waiting for inherited background PTYs, but preserve
                    # every byte already read from the native foreground CLI.
                    active_master = False
                    active_stdin = False
                    input_queue.clear()
                    if not output_queue: break
            for signum in signal_pending:
                signal_child(signum)
            signal_pending.clear()
            if resize_pending:
                resize_pending = False
                winsize = fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8))
                rows, columns, _, _ = struct.unpack('HHHH', winsize)
                try: observer.resize(columns, rows)
                except Exception: observer.disabled = True
                fcntl.ioctl(master, termios.TIOCSWINSZ, winsize)
                signal_child(signal.SIGWINCH)
            read_fds = []
            if active_stdin and active_master and len(input_queue) < max_queue:
                read_fds.append(0)
            if active_master and len(output_queue) < max_queue:
                read_fds.append(master)
            write_fds = ([master] if active_master and input_queue else [])
            if output_queue: write_fds.append(1)
            readable, writable, _ = select.select(read_fds, write_fds, [], .025)
            if 0 in readable:
                try: data = os.read(0, min(32768, max_queue - len(input_queue)))
                except BlockingIOError: data = None
                if data is not None:
                    if data: input_queue.extend(data)
                    else:
                        active_stdin = False
                        signal_child(signal.SIGHUP)
            if master in readable:
                try: data = os.read(master, min(32768, max_queue - len(output_queue)))
                except BlockingIOError: data = None
                except OSError as exc:
                    if exc.errno != errno.EIO: raise
                    data = b''
                if data is not None:
                    if data:
                        output_queue.extend(data)
                        observer.feed(data)
                        last_output = time.monotonic()
                        dirty = True
                    else: active_master = False
            for fd, queue in ((master, input_queue), (1, output_queue)):
                if fd not in writable or not queue: continue
                try: count = os.write(fd, queue)
                except BlockingIOError: continue
                except OSError as exc:
                    if fd == master and exc.errno == errno.EIO:
                        input_queue.clear()
                        active_stdin = False
                        continue
                    raise
                if count <= 0: raise OSError(errno.EIO, 'PTY write failed')
                del queue[:count]
            if dirty and (not active_master or time.monotonic() - last_output >= .025):
                observer.sample()
                dirty = False
        observer.sample()
        while child.poll() is None:
            for signum in signal_pending: signal_child(signum)
            signal_pending.clear()
            select.select([], [], [], .025)
        code = child.returncode
        return code if code >= 0 else 128 - code
    finally:
        # A hung-up outer TTY must not skip restoring handlers or reaping child.
        try: termios.tcsetattr(0, termios.TCSANOW, original)
        except (OSError, termios.error): pass
        for fd, flags in prior_flags.items():
            try: fcntl.fcntl(fd, fcntl.F_SETFL, flags)
            except OSError: pass
        for number, handler in prior_signals.items():
            signal.signal(number, handler)
        for fd in (master, slave):
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
        if child is not None and child.poll() is None:
            signal_child(signal.SIGTERM)
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                signal_child(signal.SIGKILL)
                child.wait()
