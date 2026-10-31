# Network plan for this site

**Goal (from the original note):** update the network so all traffic goes through SentinelEdgeAI.

```text
Internet
   ↓
Jio Router
   ↓
Raspberry Pi SentinelEdgeAI   (inline: a transparent bridge with two network ports)
   ↓
Switch
   ↓
All Devices
```

This is **inline placement**. The Pi sits in the cable between the router and the switch, so it can block, rate-limit, contain, quarantine and segment, not only alert.

## What is needed

1. **A second Ethernet port on the Pi.** The Pi 5 has one; add a USB 3 gigabit adapter. One port goes to the router, the other to the switch.
2. **A bridge joining the two ports**, so the Pi passes traffic through like a cable and the router still hands out addresses. On Raspberry Pi OS (NetworkManager), assuming `eth0` is the built-in port and `eth1` the adapter:

   ```bash
   sudo nmcli connection add type bridge ifname br0 con-name br0 ipv4.method auto
   sudo nmcli connection add type bridge-slave ifname eth0 master br0
   sudo nmcli connection add type bridge-slave ifname eth1 master br0
   sudo nmcli connection up br0
   ```

   Do this from the console or a keyboard and screen, not over SSH: the Pi's address changes to the bridge's.
3. **In the console → Setup:** placement **inline**, capture interface **br0**. SentinelEdgeAI then also writes its rules into the bridge table.

## The safe order

1. **Week 1, passive first.** Leave the Pi on a mirror port (or inline, but with `response_mode: monitor`). Label alerts as real or false alarms in the console.
2. **Week 2:** check **Trust** and **Operations → Response** (response tuning in `recommend`). Add your PC and anything important to `management_hosts` in the policy.
3. **Week 3:** set `FIREWALL_DRY_RUN=0` in `/etc/sentinel/sentinel.env` and use the `home` or `office` preset (`sudo sentinelctl preset office`). High-risk actions still wait for your approval.

## If the Pi fails

- **The engine or API crashes:** the watchdog removes every rule within about a minute, and traffic keeps flowing (fail-open).
- **The Pi loses power or the bridge goes down:** the network behind it goes down too, since the Pi is the cable. Keep a short cable handy to connect the router directly to the switch, or use an Ethernet bypass switch.
- **To remove every firewall rule at once:** click the mode badge (MONITOR / ENFORCING) in the top bar, then **Remove ALL blocks now** (type `CONFIRM`), or `POST /api/firewall/rollback`. This is different from `sudo sentinelctl rollback`, which returns to the previous *software version*.

## Known limits on this hardware

- About 120,000 packets/s (roughly 0.5–1 Gb/s of typical traffic). Fine for a home or office Jio connection.
- On the bridge, containment stops new connections but lets existing ones finish (no bridge conntrack in the stock kernel).
- See docs/ADMIN_GUIDE.md §3 (network placement) and docs/TROUBLESHOOTING.md.
