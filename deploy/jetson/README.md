# Jetson (brain)

`install_brain.sh` installs SentinelEdgeAI on an NVIDIA Jetson (JetPack 6.x) as the **brain**: the device that sensors report to, runs the models and hosts the console.

```bash
sudo bash deploy/jetson/install_brain.sh sentineledgeai-pi-<version>.tar.gz
```

It installs a private CPython 3.11 with `uv` (JetPack's Python may be older), installs from the package's offline wheels, and points `sentinelctl` at that interpreter through `/etc/sentinel/python`. Then choose the **Brain** role in Setup and create sensor enrolment codes (admin guide §7).

Status: built and tested in simulation and on a Raspberry Pi acting as the brain. **It has not yet run on a Jetson**, and GPU (TensorRT) models are planned for Phase 8 ([PLAN.md](../../PLAN.md)). The brain also runs CPU-only on any arm64 or x86 Linux box.

`setup_jetson.sh` is the older development setup (a virtualenv and `python main.py`) and is kept for development only.
