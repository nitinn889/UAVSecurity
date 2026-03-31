#  Debugging Telemetry Communication Issues (macOS + Raspberry Pi)

# Note: This is a problem I faced with MacOS Tahoe, later OS might not be facing this issue

##  Problem Overview

While developing a drone telemetry simulation system:

* Laptop (macOS) → sends UDP telemetry
* Raspberry Pi → receives, encrypts, and stores data

The system appeared to run correctly on both ends, but:

*  No telemetry was received on the Raspberry Pi
*  No errors were thrown in Python scripts
* SSH connection to the Pi worked perfectly

---

##  Root Cause

The issue was **not with the Python code**, but with **UDP communication from macOS**.

### Key observations:

* TCP (SSH) worked → network connectivity was fine
* UDP packets were silently not reaching the Pi
* Using `netcat (nc)` initially failed to send UDP packets

---

##  macOS `nc` (netcat) Behavior

macOS uses the **BSD version of netcat**, which behaves differently from Linux.

### This command did NOT work:

```bash
echo hello | nc -u 192.168.31.5 14550
```

###  Correct command (FIX):

```bash
echo hello | nc -u -w1 192.168.31.5 14550
```

###  Explanation:

* `-w1` sets a timeout of 1 second
* Without it, macOS may **not send UDP packets properly**

---

##  Firewall Considerations

Even when SSH works, UDP traffic can still be blocked.

### macOS Firewall Check:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
```

### Disable temporarily (for testing):

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
```

---

##  Network Behavior Insight

| Protocol        | Status                         |
| --------------- | ------------------------------ |
| TCP (SSH)       |  Allowed                      |
| UDP (Telemetry) | Initially blocked / not sent |

This highlights an important concept:

> **Successful SSH ≠ UDP communication working**

---

##  Debugging Strategy Used

1. Verified IP connectivity via SSH
2. Tested UDP using `netcat`
3. Identified macOS-specific `nc` behavior
4. Confirmed UDP works after adding `-w1`
5. Validated Python scripts after network fix

---

##  Final Outcome

After fixing the `nc` command and verifying UDP transmission:

*  Telemetry successfully reached Raspberry Pi
* Encryption + logging worked as expected
*  Full pipeline functional

---

##  Key Takeaways

* macOS `netcat` requires `-w` for UDP
* Always test UDP separately from your app
* SSH working does NOT guarantee UDP works
* Debug networking before debugging application logic

---

## Future Improvements

* Add automated network diagnostics
* Implement retry/ack mechanism for UDP
* Use TCP fallback for reliability
* Integrate real telemetry protocols (e.g., MAVLink)

---

##  Conclusion

This issue reinforced the importance of:

> **System-level debugging before code-level debugging**

A small platform-specific behavior (macOS `nc`) caused a complete communication failure, despite correct application logic.

---
