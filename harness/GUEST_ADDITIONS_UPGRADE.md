# Guest Additions Upgrade: Fix Shared Folder

Your host has VirtualBox **7.2.8**. The VM has an older Guest Additions version —
the vboxsf module won't load, so SDNResearch can't mount.

Run these commands **inside the Ubuntu VM**.

---

## Step 1 — Install kernel headers (required to build vboxsf)

```bash
sudo apt-get update
sudo apt-get install -y build-essential dkms \
    linux-headers-$(uname -r)
```

If apt can't reach the internet, check that the VM's network adapter is
set to NAT (VirtualBox > Settings > Network > Adapter 1: NAT).

---

## Step 2 — Insert the Guest Additions ISO from the host

In the VirtualBox menu bar (top of the VM window):

```
Devices > Insert Guest Additions CD Image...
```

This mounts the 7.2.8 ISO from your host installation.

---

## Step 3 — Mount and run the installer

```bash
# Find the mount point (usually auto-mounted):
ls /media/$USER/

# If not auto-mounted, mount manually:
sudo mkdir -p /mnt/cdrom
sudo mount /dev/cdrom /mnt/cdrom

# Run the installer (adjust path to match your mount point):
sudo /media/$USER/VBox_GAs_7.2.8/VBoxLinuxAdditions.run
# OR if manually mounted:
sudo /mnt/cdrom/VBoxLinuxAdditions.run
```

Expected output ends with:
```
VirtualBox Guest Additions: Starting.
```

---

## Step 4 — Reboot

```bash
sudo reboot
```

---

## Step 5 — Verify the shared folder mounts

After reboot:

```bash
# Check the module loaded:
lsmod | grep vboxsf

# Check the folder mounted:
ls /media/sf_SDNResearch/
# OR:
ls ~/SDNResearch/
```

If the folder is not mounted, force it:

```bash
sudo mount -t vboxsf SDNResearch /media/sf_SDNResearch
```

If you get "Protocol error", the folder name in VirtualBox settings must
match exactly. Check:
```
VirtualBox > Settings > Shared Folders
```
The Machine Folder name there is what you pass to mount -t vboxsf.

---

## Step 6 — Confirm version match

```bash
VBoxClient --version
# Should output: 7.2.8_Ubuntu r...
```

Once `ls /media/sf_SDNResearch/` shows your files, the shared folder is
working. Copy the harness folder from the host into `~/sdn-thesis/` on
the VM:

```bash
cp -r /media/sf_SDNResearch/harness ~/sdn-thesis/
chmod +x ~/sdn-thesis/harness/scripts/*.sh
```

---

## Fallback: push via git (if shared folder still fails)

On your **host** machine (in this folder):
```bash
cd "C:\Users\aiman\Documents\Claude\Projects\SDN Research Paper\harness"
git init && git add . && git commit -m "experiment harness"
git remote add origin https://github.com/aimannurzharfan/sdn-multi-window-ddos.git
git push origin main
```

Then inside the VM:
```bash
cd ~/sdn-thesis && git pull
```
