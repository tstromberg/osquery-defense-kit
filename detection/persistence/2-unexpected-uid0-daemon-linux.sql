-- Unexpected long-running processes running as root
--
-- false positives:
--   * new software requiring escalated privileges
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/
--
-- tags: persistent process state
-- platform: linux
SELECT
  CONCAT (
    p0.name,
    ',',
    REPLACE(
      p0.path,
      COALESCE(
        REGEX_MATCH (p0.path, "/nix/store/(.*?)/.*", 1),
        REGEX_MATCH (p0.path, "(\d[\.\d]+)", 1),
        "3.11"
      ),
      "__VERSION__"
    ),
    ',',
    -- This is intentionally not euid, as everything is euid 0
    p0.uid,
    ',',
    CONCAT (
      SPLIT (p0.cgroup_path, "/", 0),
      ",",
      SPLIT (p0.cgroup_path, "/", 1)
    ),
    ',',
    f.mode
  ) AS exception_key,
  DATETIME(f.ctime, 'unixepoch') AS p0_changed,
  DATETIME(f.mtime, 'unixepoch') AS p0_modified,
  (strftime('%s', 'now') - p0.start_time) AS p0_runtime_s,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.euid = 0
  AND p0.parent > 0
  AND p0.path != ""
  AND p0.start_time < (strftime('%s', 'now') - 3600)
  AND exception_key NOT IN (
    '(sd-pam),/usr/lib/systemd/systemd,0,user.slice,user-0.slice,0755',
    '(sd-pam),/usr/lib/systemd/systemd-executor,0,user.slice,user-0.slice,0755',
    '(udev-worker),/usr/bin/udevadm,0,system.slice,systemd-udevd.service,0755',
    '.tailscaled-wra,/nix/store/__VERSION__/bin/.tailscaled-wrapped,0,system.slice,tailscaled.service,0555',
    '/usr/bin/monito,/usr/bin/perl,0,system.slice,monitorix.service,0755',
    'abrt-dump-journ,/usr/bin/abrt-dump-journal-core,0,system.slice,abrt-journal-core.service,0755',
    'abrt-dump-journ,/usr/bin/abrt-dump-journal-oops,0,system.slice,abrt-oops.service,0755',
    'abrt-dump-journ,/usr/bin/abrt-dump-journal-xorg,0,system.slice,abrt-xorg.service,0755',
    'abrtd,/usr/sbin/abrtd,0,system.slice,abrtd.service,0755',
    'accounts-daemon,/nix/store/__VERSION__/libexec/accounts-daemon,0,system.slice,accounts-daemon.service,0555',
    'accounts-daemon,/usr/lib/accounts-daemon,0,system.slice,accounts-daemon.service,0755',
    'accounts-daemon,/usr/libexec/accounts-daemon,0,system.slice,accounts-daemon.service,0755',
    'acpid,/usr/sbin/acpid,0,system.slice,acpid.service,0755',
    'agetty,/nix/store/__VERSION__/bin/agetty,0,system.slice,system-getty.slice,0555',
    'agetty,/usr/bin/agetty,0,system.slice,system-getty.slice,0755',
    'agetty,/usr/sbin/agetty,0,system.slice,system-getty.slice,0755',
    'agetty,/usr/sbin/agetty,0,system.slice,system-serial\x2dgetty.slice,0755',
    'alsactl,/usr/sbin/alsactl,0,system.slice,alsa-state.service,0755',
    'anacron,/usr/bin/anacron,0,system.slice,cronie.service,0755',
    'iotop,/usr/sbin/iotop-c,0,user.slice,user-1000.slice,0755',
    'anacron,/usr/sbin/anacron,0,system.slice,anacron.service,0755',
    'anacron,/usr/sbin/anacron,0,system.slice,crond.service,0755',
    'apache2,/usr/sbin/apache2,0,system.slice,apache2.service,0755',
    'apcupsd,/usr/bin/apcupsd,0,system.slice,apcupsd.service,0755',
    'apt,/usr/bin/apt,0,user.slice,user-1000.slice,0755',
    'apt.systemd.dai,/usr/bin/dash,0,system.slice,apt-daily-upgrade.service,0755',
    'atd,/usr/sbin/atd,0,system.slice,atd.service,0755',
    'atop,/usr/bin/atop,0,system.slice,atop.service,0755',
    'atopacctd,/usr/sbin/atopacctd,0,system.slice,atopacct.service,0755',
    'auditd,/usr/bin/auditd,0,system.slice,auditd.service,0755',
    'auditd,/usr/sbin/auditd,0,system.slice,auditd.service,0750',
    'auditd,/usr/sbin/auditd,0,system.slice,auditd.service,0755',
    'bash,/usr/bin/bash,0,user.slice,user-1000.slice,0755',
    'blueman-mechani,/usr/bin/python__VERSION__,0,system.slice,blueman-mechanism.service,0755',
    'blueman-mechanism.service,Bluetooth management mechanism,,200',
    'bluetoothd,/usr/lib/bluetooth/bluetoothd,0,system.slice,bluetooth.service,0755',
    'bluetoothd,/usr/libexec/bluetooth/bluetoothd,0,system.slice,bluetooth.service,0755',
    'boltd,/usr/lib/boltd,0,system.slice,bolt.service,0755',
    'boltd,/usr/libexec/boltd,0,system.slice,bolt.service,0755',
    'bpfilter_umh,/bpfilter_umh,0,,,',
    'canonical-livep,/snap/canonical-livepatch/__VERSION__/canonical-livepatchd,0,system.slice,snap.canonical-livepatch.canonical-livepatchd.service,0755',
    'cat,/usr/bin/cat,0,user.slice,user-0.slice,0755',
    'chainctl,/usr/local/bin/chainctl,0,user.slice,user-1000.slice,0755',
    'containerd,/nix/store/__VERSION__/bin/containerd,0,system.slice,docker.service,0555',
    'containerd,/usr/bin/containerd,0,system.slice,containerd.service,0755',
    'containerd,/usr/bin/containerd,0,system.slice,docker.service,0755',
    'containerd,/usr/sbin/containerd,0,system.slice,docker.service,0755',
    'containerd-shim,/usr/bin/containerd-shim-runc-v2,0,system.slice,containerd.service,0755',
    'containerd-shim,/usr/bin/containerd-shim-runc-v2,0,system.slice,docker.service,0755',
    'cron,/usr/sbin/cron,0,system.slice,cron.service,0755',
    'crond,/usr/bin/crond,0,system.slice,cronie.service,0755',
    'crond,/usr/sbin/crond,0,system.slice,crond.service,0755',
    'cups-browsed,/usr/sbin/cups-browsed,0,system.slice,cups-browsed.service,0755',
    'cups-proxyd,/snap/cups/__VERSION__/sbin/cups-proxyd,0,system.slice,snap.cups.cupsd.service,0755',
    'cupsd,/snap/cups/__VERSION__/sbin/cupsd,0,system.slice,snap.cups.cupsd.service,0700',
    'cupsd,/usr/bin/cupsd,0,system.slice,cups.service,0700',
    'cupsd,/usr/sbin/cupsd,0,system.slice,cups.service,0755',
    'cupsd,/usr/sbin/cupsd,0,system.slice,system-cups.slice,0700',
    'cupsd,/usr/sbin/cupsd,0,system.slice,system-cups.slice,0755',
    'dbus-daemon,/usr/bin/dbus-daemon,0,user.slice,user-0.slice,0755',
    'dbus-daemon,/usr/bin/dbus-daemon,0,user.slice,user-1000.slice,0755',
    'dbus-launch,/usr/bin/dbus-launch,0,user.slice,user-1000.slice,0755',
    'dconf-service,/usr/libexec/dconf-service,0,user.slice,user-1000.slice,0755',
    'dhclient,/usr/sbin/dhclient,0,system.slice,networking.service,0755',
    'dhcpcd,/nix/store/__VERSION__/bin/dhcpcd,0,system.slice,dhcpcd.service,0555',
    'dirmngr,/usr/bin/dirmngr,0,system.slice,archlinux-keyring-wkd-sync.service,0755',
    'dirmngr,/usr/bin/dirmngr,0,system.slice,system-dirmngr.slice,0755',
    'DisplayLinkMana,/usr/libexec/displaylink/DisplayLinkManager,0,system.slice,displaylink.service,0755',
    'dmeventd,/usr/sbin/dmeventd,0,system.slice,dm-event.service,0755',
    'dnf,/usr/bin/python__VERSION__,0,user.slice,user-1000.slice,0755',
    'dnsmasq,/usr/bin/dnsmasq,0,system.slice,libvirtd.service,0755',
    'dnsmasq,/usr/sbin/dnsmasq,0,system.slice,libvirtd.service,0755',
    'doas,/usr/bin/doas,1000,user.slice,user-1000.slice,4755',
    'docker,/usr/bin/docker,0,user.slice,user-1000.slice,0755',
    'docker,/usr/local/bin/docker,0,user.slice,user-1000.slice,0755',
    'docker-proxy,/usr/bin/docker-proxy,0,system.slice,docker.service,0755',
    'docker-proxy,/usr/libexec/docker/docker-proxy,0,system.slice,docker.service,0755',
    'dockerd,/nix/store/__VERSION__/libexec/docker/dockerd,0,system.slice,docker.service,0555',
    'dockerd,/snap/docker/__VERSION__/bin/dockerd,0,system.slice,snap.docker.dockerd.service,0755',
    'dockerd,/usr/bin/dockerd,0,system.slice,docker.service,0755',
    'dockerd,/usr/sbin/dockerd,0,system.slice,docker.service,0755',
    'dpkg,/usr/bin/dpkg,0,user.slice,user-1000.slice,0755',
    'elastic-endpoin,/opt/Elastic/Endpoint/elastic-endpoint,0,elasticendpoint,,0500',
    'elastic-endpoin,/opt/Elastic/Endpoint/elastic-endpoint,0,system.slice,ElasticEndpoint.service,0500',
    'elastic-endpoin,/var/opt/Elastic/Endpoint/elastic-endpoint,0,elasticendpoint,,0500',
    'execsnoop-bpfcc,/usr/bin/python__VERSION__,0,system.slice,com.system76.Scheduler.service,0755',
    'firewalld,/usr/bin/python__VERSION__,0,system.slice,firewalld.service,0755',
    'fish,/usr/bin/fish,0,user.slice,user-1000.slice,0755',
    'flatpak-system-,/usr/lib/flatpak-system-helper,0,system.slice,flatpak-system-helper.service,0755',
    'flatpak-system-,/usr/libexec/flatpak-system-helper,0,system.slice,flatpak-system-helper.service,0755',
    'flatpak-system-,/usr/libexec/flatpak-system-helper,0,user.slice,user-0.slice,0755',
    'flock,/usr/bin/flock,0,system.slice,system-btrfs\x2ddedup.slice,0755',
    'fprintd,/usr/libexec/fprintd,0,system.slice,fprintd.service,0755',
    'frontend,/usr/bin/perl,0,user.slice,user-1000.slice,0755',
    'fstrim,/usr/sbin/fstrim,0,system.slice,fstrim.service,0755',
    'fusermount,/usr/bin/fusermount,1000,user.slice,user-1000.slice,4755',
    'fwupd,/usr/lib/fwupd/fwupd,0,system.slice,fwupd.service,0755',
    'fwupd,/usr/libexec/fwupd/fwupd,0,system.slice,fwupd.service,0755',
    'gdisk,/usr/sbin/gdisk,0,user.slice,user-1000.slice,0755',
    'gdm,/usr/bin/gdm,0,system.slice,gdm.service,0755',
    'gdm,/usr/sbin/gdm,0,system.slice,display-manager.service,0755',
    'gdm,/usr/sbin/gdm,0,system.slice,gdm.service,0755',
    'gdm-session-wor,/usr/lib/gdm-session-worker,0,user.slice,user-1000.slice,0755',
    'gdm-session-wor,/usr/lib/gdm-session-worker,0,user.slice,user-120.slice,0755',
    'gdm-session-wor,/usr/libexec/gdm-session-worker,0,user.slice,user-1000.slice,0755',
    'gdm-session-wor,/usr/libexec/gdm-session-worker,0,user.slice,user-1001.slice,0755',
    'gdm-session-wor,/usr/libexec/gdm-session-worker,0,user.slice,user-120.slice,0755',
    'gdm-session-wor,/usr/libexec/gdm-session-worker,0,user.slice,user-128.slice,0755',
    'gdm-session-wor,/usr/libexec/gdm-session-worker,0,user.slice,user-42.slice,0755',
    'gdm-session-wor,/usr/libexec/gdm/gdm-session-worker,0,user.slice,user-1000.slice,0755',
    'gdm-session-wor,/usr/libexec/gdm/gdm-session-worker,0,user.slice,user-463.slice,0755',
    'gdm3,/usr/sbin/gdm3,0,system.slice,gdm.service,0755',
    'geoclue.service,Location Lookup Service,geoclue,500',
    'gnome-keyring-d,/usr/bin/gnome-keyring-daemon,0,user.slice,user-1000.slice,0755',
    'gpg-agent,/usr/bin/gpg-agent,0,system.slice,fwupd.service,0755',
    'gpg-agent,/usr/bin/gpg-agent,0,system.slice,packagekit.service,0755',
    'gpg-agent,/usr/bin/gpg-agent,0,user.slice,user-1000.slice,0755',
    'greetd,/usr/sbin/greetd,0,system.slice,greetd.service,0755',
    'greetd,/usr/sbin/greetd,0,user.slice,user-1000.slice,0755',
    'group-admin-dae,/usr/libexec/group-admin-daemon,0,system.slice,group-admin-daemon.service,0755',
    'gssproxy,/usr/sbin/gssproxy,0,system.slice,gssproxy.service,0755',
    'gvfsd,/usr/libexec/gvfsd,0,user.slice,user-1000.slice,0755',
    'gvfsd-fuse,/usr/libexec/gvfsd-fuse,0,user.slice,user-1000.slice,0755',
    'haproxy,/usr/sbin/haproxy,0,system.slice,haproxy.service,0755',
    'iio-sensor-prox,/usr/lib/iio-sensor-proxy,0,system.slice,iio-sensor-proxy.service,0755',
    'iio-sensor-prox,/usr/libexec/iio-sensor-proxy,0,system.slice,iio-sensor-proxy.service,0755',
    'incusd,/opt/incus/bin/incusd,0,lxc.monitor.dashing-bat,,0755',
    'incusd,/opt/incus/bin/incusd,0,lxc.monitor.j1,,0755',
    'incusd,/opt/incus/bin/incusd,0,lxc.monitor.j1c,,0755',
    'incusd,/opt/incus/bin/incusd,0,system.slice,incus.service,0755',
    'incusd,/usr/libexec/incus/incusd,0,lxc.monitor.cheerful-parakeet,,0755',
    'incusd,/usr/libexec/incus/incusd,0,lxc.monitor.pure-dodo,,0755',
    'incusd,/usr/libexec/incus/incusd,0,system.slice,incus.service,0755',
    'indicator-cpufr,/usr/bin/python__VERSION__,0,system.slice,dbus.service,0755',
    'input-remapper-,/usr/bin/python__VERSION__,0,system.slice,input-remapper.service,0755',
    'ir_agent,/opt/rapid7/ir_agent/components/insight_agent/__VERSION__/ir_agent,0,system.slice,ir_agent.service,',
    'ir_agent,/opt/rapid7/ir_agent/components/insight_agent/__VERSION__/ir_agent,0,system.slice,ir_agent.service,0700',
    'ir_agent,/opt/rapid7/ir_agent/ir_agent,0,system.slice,ir_agent.service,',
    'ir_agent,/opt/rapid7/ir_agent/ir_agent,0,system.slice,ir_agent.service,0700',
    'irqbalance,/usr/sbin/irqbalance,0,system.slice,irqbalance.service,0755',
    'iwd,/usr/lib/iwd/iwd,0,system.slice,iwd.service,0755',
    'journalctl,/usr/bin/journalctl,0,user.slice,user-1000.slice,0755',
    'just,/usr/bin/just,0,user.slice,user-1000.slice,0755',
    'keyd,/usr/local/bin/keyd,0,system.slice,keyd.service,0755',
    'launcher,/opt/kolide-k2/bin/launcher,0,system.slice,launcher.kolide-k2.service,0755',
    'launcher,/opt/kolide-k2/bin/launcher-updates/__VERSION__/launcher,0,system.slice,launcher.kolide-k2.service,0755',
    'launcher,/usr/lib/opt/kolide-k2/bin/launcher,0,system.slice,launcher.kolide-k2.service,0755',
    'launcher,/usr/local/kolide-k2/bin/launcher,0,system.slice,launcher.kolide-k2.service,0755',
    'launcher,/usr/local/kolide-k2/bin/launcher-updates/__VERSION__/launcher,0,system.slice,launcher.kolide-k2.service,0755',
    'launcher,/var/kolide-k2/k2device.kolide.com/updates/launcher/__VERSION__/launcher,0,system.slice,launcher.kolide-k2.service,0755',
    'launcher,/var/vanta/launcher,0,system.slice,vanta.service,0755',
    'libvirtd,/usr/bin/libvirtd,0,system.slice,libvirtd.service,0755',
    'libvirtd,/usr/sbin/libvirtd,0,system.slice,libvirtd.service,0755',
    'lightdm,/nix/store/__VERSION__/bin/lightdm,0,system.slice,display-manager.service,0555',
    'lightdm,/nix/store/__VERSION__/bin/lightdm,0,user.slice,user-1000.slice,0555',
    'lightdm,/nix/store/__VERSION__/bin/lightdm,0,user.slice,user-78.slice,0555',
    'lightdm,/usr/bin/lightdm,0,system.slice,lightdm.service,0755',
    'lightdm,/usr/bin/lightdm,0,user.slice,user-1000.slice,0755',
    'lightdm,/usr/bin/lightdm,0,user.slice,user-974.slice,0755',
    'lightdm,/usr/sbin/lightdm,0,system.slice,lightdm.service,0755',
    'lightdm,/usr/sbin/lightdm,0,user.slice,user-1000.slice,0755',
    'lima-guestagent,/usr/local/bin/lima-guestagent,0,system.slice,lima-guestagent.service,0755',
    'login,/usr/bin/login,0,user.slice,user-1000.slice,0755',
    'low-memory-moni,/usr/libexec/low-memory-monitor,0,system.slice,low-memory-monitor.service,0755',
    'lxc-monitord,/usr/lib/x86_64-linux-gnu/lxc/lxc-monitord,0,system.slice,lxc-monitord.service,0755',
    'lxc-monitord,/usr/libexec/lxc/lxc-monitord,0,system.slice,lxc-monitord.service,0755',
    'lxcfs,/opt/incus/bin/lxcfs,0,system.slice,incus-lxcfs.service,0755',
    'lxcfs,/usr/bin/lxcfs,0,system.slice,lxcfs.service,',
    'lxcfs,/usr/bin/lxcfs,0,system.slice,lxcfs.service,0755',
    'make,/usr/bin/make,0,user.slice,user-1000.slice,0755',
    'mbim-proxy,/usr/libexec/mbim-proxy,0,system.slice,ModemManager.service,0755',
    'mc,/usr/bin/mc,0,user.slice,user-0.slice,0755',
    'mcelog,/usr/sbin/mcelog,0,system.slice,mcelog.service,0755',
    'metalauncher,/var/vanta/metalauncher,0,system.slice,vanta.service,0755',
    'mintUpdate,/usr/bin/python__VERSION__,0,user.slice,user-1000.slice,0755',
    'ModemManager,/usr/sbin/ModemManager,0,system.slice,ModemManager.service,0755',
    'mount.ntfs,/usr/bin/ntfs-3g,0,system.slice,udisks2.service,0755',
    'mpris-proxy,/usr/bin/mpris-proxy,0,user.slice,user-0.slice,0755',
    'multipassd,/snap/multipass/__VERSION__/bin/multipassd,0,system.slice,snap.multipass.multipassd.service,0755',
    'multipathd,/usr/sbin/multipathd,0,system.slice,multipathd.service,0755',
    'nessus-service,/opt/nessus/sbin/nessus-service,0,system.slice,nessusd.service,0755',
    'nessusd,/opt/nessus/sbin/nessusd,0,system.slice,nessusd.service,0755',
    'networkd-dispat,/usr/bin/python__VERSION__,0,system.slice,networkd-dispatcher.service,0755',
    'NetworkManager,/usr/bin/NetworkManager,0,system.slice,NetworkManager.service,0755',
    'NetworkManager,/usr/sbin/NetworkManager,0,system.slice,NetworkManager.service,0755',
    'newgrp,/usr/bin/newgrp,1000,user.slice,user-1000.slice,4755',
    'nix-daemon,/nix/store/__VERSION__/bin/nix,0,system.slice,nix-daemon.service,0555',
    'nm-dispatcher,/usr/lib/nm-dispatcher,0,system.slice,NetworkManager-dispatcher.service,0755',
    'nm-dispatcher,/usr/libexec/nm-dispatcher,0,system.slice,NetworkManager-dispatcher.service,0755',
    'nm-openvpn-serv,/usr/libexec/nm-openvpn-service,0,system.slice,NetworkManager.service,0755',
    'nvidia-powerd,/usr/bin/nvidia-powerd,0,system.slice,nvidia-powerd.service,0755',
    'ollama,/snap/ollama/__VERSION__/bin/ollama,0,system.slice,snap.ollama.listener.service,0755',
    'ollama_llama_se,/tmp/ollama__VERSION__/runners/cpu_avx2/ollama_llama_server,0,system.slice,snap.ollama.listener.service,',
    'orbit,/opt/orbit/bin/orbit/linux/stable/orbit,0,system.slice,orbit.service,0755',
    'osquery-extensi,/nix/store/__VERSION__/bin/osquery-extension.ext,0,system.slice,kolide-launcher.service,0555',
    'osquery-vanta.e,/var/vanta/osquery-vanta.ext,0,system.slice,vanta.service,0755',
    'osqueryd,/nix/store/__VERSION__/bin/osqueryd,0,system.slice,kolide-launcher.service,0555',
    'osqueryd,/opt/orbit/bin/osqueryd/linux/stable/osqueryd,0,system.slice,orbit.service,0755',
    'osqueryd,/usr/lib/opt/kolide-k2/bin/osqueryd,0,system.slice,launcher.kolide-k2.service,0755',
    'osqueryd,/usr/local/kolide-k2/bin/osqueryd,0,system.slice,launcher.kolide-k2.service,0755',
    'osqueryd,/usr/local/kolide-k2/bin/osqueryd-updates/__VERSION__/osqueryd,0,system.slice,launcher.kolide-k2.service,0755',
    'osqueryd,/var/kolide-k2/k2device.kolide.com/updates/osqueryd/__VERSION__/osqueryd,0,system.slice,launcher.kolide-k2.service,0755',
    'osqueryd,/var/vanta/osqueryd,0,system.slice,vanta.service,0755',
    'osqueryi,/usr/bin/osqueryd,0,user.slice,user-1000.slice,0755',
    'osqueryi,/var/usrlocal/bin/osqueryi,0,user.slice,user-1000.slice,0755',
    'ostree,/usr/bin/ostree,0,system.slice,ostree-finalize-staged-hold.service,0755',
    'packagekitd,/usr/libexec/packagekitd,0,system.slice,packagekit.service,0755',
    'pacman,/usr/bin/pacman,0,user.slice,user-1000.slice,0755',
    'pcscd,/snap/yubioath-desktop/__VERSION__/usr/sbin/pcscd,0,system.slice,snap.yubioath-desktop.pcscd.service,0755',
    'pcscd,/usr/sbin/pcscd,0,system.slice,pcscd.service,0755',
    'perl,/nix/store/__VERSION__/bin/perl,0,system.slice,znapzend.service,0555',
    'pmdakvm,/usr/libexec/pcp/pmdas/kvm/pmdakvm,0,system.slice,pmcd.service,0755',
    'pmdalinux,/usr/libexec/pcp/pmdas/linux/pmdalinux,0,system.slice,pmcd.service,0755',
    'pmdaproc,/usr/libexec/pcp/pmdas/proc/pmdaproc,0,system.slice,pmcd.service,0755',
    'pmdaroot,/usr/libexec/pcp/pmdas/root/pmdaroot,0,system.slice,pmcd.service,0755',
    'pmdaxfs,/usr/libexec/pcp/pmdas/xfs/pmdaxfs,0,system.slice,pmcd.service,0755',
    'podman,/usr/bin/podman,0,system.slice,podman.service,0755',
    'polkitd,/usr/libexec/polkitd,0,system.slice,polkit.service,0755',
    'pop-system-upda,/usr/bin/pop-system-updater,0,system.slice,com.system76.SystemUpdater.service,0755',
    'power-profiles-,/usr/lib/power-profiles-daemon,0,system.slice,power-profiles-daemon.service,0755',
    'power-profiles-,/usr/libexec/power-profiles-daemon,0,system.slice,power-profiles-daemon.service,0755',
    'pwrstatd,/usr/sbin/pwrstatd,0,system.slice,pwrstatd.service,0700',
    'python3,/usr/bin/python__VERSION__,0,system.slice,dbus.service,0755',
    'python3,/usr/bin/python__VERSION__,0,system.slice,system-dbus\x2d:1.1\x2dorg.pop_os.transition_system.slice,0755',
    'python3,/usr/bin/python__VERSION__,0,system.slice,system-dbus\x2d:1.2\x2dorg.pop_os.transition_system.slice,0755',
    'python3,/usr/bin/python__VERSION__,0,system.slice,ubuntu-advantage.service,0755',
    'qemu-ga,/usr/bin/qemu-ga,0,system.slice,qemu-guest-agent.service,0755',
    'qemu-nbd,/usr/bin/qemu-nbd,0,user.slice,user-1000.slice,0755',
    'qualys-cloud-ag,/usr/local/qualys/cloud-agent/bin/qualys-cloud-agent,0,system.slice,qualys-cloud-agent.service,0700',
    'rapid7_endpoint,/opt/rapid7/ir_agent/components/endpoint_broker/__VERSION__/rapid7_endpoint_broker,0,system.slice,ir_agent.service,0744',
    'rpm-ostree,/usr/bin/rpm-ostree,0,system.slice,rpm-ostreed.service,0755',
    'rsyslogd,/usr/sbin/rsyslogd,0,system.slice,rsyslog.service,0755',
    'run-cups-browse,/usr/bin/dash,0,system.slice,snap.cups.cups-browsed.service,0755',
    'run-cupsd,/usr/bin/dash,0,system.slice,snap.cups.cupsd.service,0755',
    'runc,/usr/bin/runc,0,system.slice,docker.service,0755',
    'scdaemon,/usr/libexec/scdaemon,0,system.slice,packagekit.service,0755',
    'scdaemon,/usr/libexec/scdaemon,0,user.slice,user-1000.slice,0755',
    'sddm,/usr/bin/sddm,0,system.slice,sddm.service,0755',
    'sddm-helper,/usr/lib/sddm/sddm-helper,0,user.slice,user-1000.slice,0755',
    'sddm-helper,/usr/lib/x86_64-linux-gnu/sddm/sddm-helper,0,user.slice,user-1000.slice,0755',
    'sddm-helper,/usr/lib/x__VERSION___64-linux-gnu/sddm/sddm-helper,0,user.slice,user-1000.slice,0755',
    'sddm-helper,/usr/libexec/sddm-helper,0,user.slice,user-1000.slice,0755',
    'sedispatch,/usr/sbin/sedispatch,0,system.slice,auditd.service,0755',
    'sg,/usr/bin/newgrp,1000,user.slice,user-1000.slice,4755',
    'sh,/nix/store/__VERSION__/bin/bash,0,system.slice,znapzend.service,0555',
    'sleep,/usr/bin/sleep,0,system.slice,snap.cups.cups-browsed.service,0755',
    'sleep,/usr/bin/sleep,0,system.slice,system-btrfs\x2ddedup.slice,0755',
    'smartd,/usr/sbin/smartd,0,system.slice,smartd.service,0755',
    'smartd,/usr/sbin/smartd,0,system.slice,smartmontools.service,0755',
    'snapd,/snap/snapd/__VERSION__/usr/lib/snapd/snapd,0,system.slice,snapd.service,0755',
    'snapd,/usr/lib/snapd/snapd,0,system.slice,snapd.service,0755',
    'snapd,/usr/libexec/snapd/snapd,0,system.slice,snapd.service,0755',
    'ssh,/nix/store/__VERSION__/bin/ssh,0,system.slice,znapzend.service,0555',
    'sshd,/nix/store/__VERSION__/bin/sshd,0,system.slice,sshd.service,0555',
    'sshd,/nix/store/__VERSION__/bin/sshd,0,user.slice,user-1000.slice,0555',
    'sshd,/usr/bin/sshd,0,system.slice,sshd.service,0755',
    'sshd,/usr/bin/sshd,0,user.slice,user-1000.slice,0755',
    'sshd,/usr/sbin/sshd,0,system.slice,ssh.service,0755',
    'sshd,/usr/sbin/sshd,0,system.slice,sshd.service,0755',
    'sshd,/usr/sbin/sshd,0,user.slice,user-1000.slice,0755',
    'sshd,/usr/sbin/sshd,0,user.slice,user-501.slice,0755',
    'sshd-session,/usr/lib/openssh/sshd-session,0,user.slice,user-1000.slice,0755',
    'sssd_kcm,/usr/libexec/sssd/sssd_kcm,0,system.slice,sssd-kcm.service,0755',
    'su,/usr/bin/su,0,user.slice,user-0.slice,4755',
    'su,/usr/bin/su,0,user.slice,user-1000.slice,4755',
    'su,/usr/bin/su,1000,user.slice,user-0.slice,4755',
    'sudo,/usr/bin/sudo,1000,user.slice,user-1000.slice,4111',
    'sudo,/usr/bin/sudo,1000,user.slice,user-1000.slice,4755',
    'sudo,/usr/bin/sudo,1001,user.slice,user-0.slice,4111',
    'supergfxd,/usr/bin/supergfxd,0,system.slice,supergfxd.service,0755',
    'switcheroo-cont,/usr/libexec/switcheroo-control,0,system.slice,switcheroo-control.service,0755',
    'system76-power,/usr/bin/system76-power,0,system.slice,com.system76.PowerDaemon.service,0755',
    'system76-power,/usr/bin/system__VERSION__-power,0,system.slice,com.system76.PowerDaemon.service,0755',
    'system76-schedu,/usr/bin/system76-scheduler,0,system.slice,com.system76.Scheduler.service,0755',
    'system76-schedu,/usr/bin/system__VERSION__-scheduler,0,system.slice,com.system76.Scheduler.service,0755',
    'systemd,/usr/lib/systemd/systemd,0,user.slice,user-0.slice,0755',
    'systemd-coredum,/nix/store/__VERSION__/lib/systemd/systemd-coredump,0,,,0555',
    'systemd-homed,/usr/lib/systemd/systemd-homed,0,system.slice,systemd-homed.service,0755',
    'systemd-hostnam,/usr/lib/systemd/systemd-hostnamed,0,system.slice,systemd-hostnamed.service,0755',
    'systemd-journal,/nix/store/__VERSION__/lib/systemd/systemd-journald,0,system.slice,systemd-journald.service,0555',
    'systemd-journal,/usr/lib/systemd/systemd-journald,0,system.slice,systemd-journald.service,0755',
    'systemd-localed,/usr/lib/systemd/systemd-localed,0,system.slice,systemd-localed.service,0755',
    'systemd-logind,/nix/store/__VERSION__/lib/systemd/systemd-logind,0,system.slice,systemd-logind.service,0555',
    'systemd-logind,/usr/lib/systemd/systemd-logind,0,system.slice,systemd-logind.service,0755',
    'systemd-machine,/usr/lib/systemd/systemd-machined,0,system.slice,systemd-machined.service,0755',
    'systemd-nspawn,/usr/bin/systemd-nspawn,0,machine.slice,systemd-nspawn@chainguard-systembase.service,0755',
    'systemd-nspawn,/usr/bin/systemd-nspawn,0,machine.slice,systemd-nspawn@foo.service,0755',
    'systemd-nsresou,/usr/lib/systemd/systemd-nsresourced,0,system.slice,systemd-nsresourced.service,0755',
    'systemd-nsresou,/usr/lib/systemd/systemd-nsresourcework,0,system.slice,systemd-nsresourced.service,0755',
    'systemd-sleep,/usr/lib/systemd/systemd-sleep,0,system.slice,systemd-suspend.service,0755',
    'systemd-udevd,/nix/store/__VERSION__/bin/udevadm,0,system.slice,systemd-udevd.service,0555',
    'systemd-udevd,/usr/bin/udevadm,0,system.slice,systemd-udevd.service,0755',
    'systemd-userdbd,/usr/lib/systemd/systemd-userdbd,0,system.slice,systemd-userdbd.service,0755',
    'systemd-userwor,/usr/lib/systemd/systemd-userwork,0,system.slice,systemd-userdbd.service,0755',
    'tailscaled,/usr/bin/tailscaled,0,system.slice,tailscaled.service,0755',
    'tailscaled,/usr/sbin/tailscaled,0,system.slice,tailscaled.service,0755',
    'tcpdump,/usr/bin/tcpdump,0,user.slice,user-1000.slice,0755',
    'thermald,/usr/sbin/thermald,0,system.slice,thermald.service,0755',
    'touchegg,/usr/bin/touchegg,0,system.slice,touchegg.service,0755',
    'tuned,/usr/bin/python__VERSION__,0,system.slice,tuned.service,0755',
    'tuned-ppd,/usr/bin/python__VERSION__,0,system.slice,tuned-ppd.service,0755',
    'ubuntu-advantag,/usr/libexec/ubuntu-advantage-desktop-daemon,0,system.slice,ubuntu-advantage-desktop-daemon.service,0755',
    'udisksd,/nix/store/__VERSION__/libexec/udisks2/udisksd,0,system.slice,udisks2.service,0555',
    'udisksd,/usr/lib/udisks2/udisksd,0,system.slice,udisks2.service,0755',
    'udisksd,/usr/libexec/udisks2/udisksd,0,system.slice,udisks2.service,0755',
    'unattended-upgr,/usr/bin/python__VERSION__,0,system.slice,apt-daily-upgrade.service,0755',
    'unattended-upgr,/usr/bin/python__VERSION__,0,system.slice,unattended-upgrades.service,0755',
    'upowerd,/usr/lib/upowerd,0,system.slice,upower.service,0755',
    'upowerd,/usr/libexec/upower/upowerd,0,system.slice,upower.service,0755',
    'upowerd,/usr/libexec/upowerd,0,system.slice,upower.service,0755',
    'uresourced,/usr/libexec/uresourced,0,system.slice,uresourced.service,0755',
    'v4l2-relayd,/usr/bin/v4l2-relayd,0,system.slice,v4l2-relayd.service,0755',
    'velociraptor_cl,/usr/local/bin/velociraptor,0,system.slice,velociraptor_client.service,0700',
    'vim,/usr/bin/vim.basic,0,user.slice,user-1000.slice,0755',
    'virtiofsd,/opt/incus/bin/virtiofsd,0,system.slice,incus.service,0755',
    'virtlockd,/usr/sbin/virtlockd,0,system.slice,virtlockd.service,0755',
    'virtlogd,/usr/bin/virtlogd,0,system.slice,virtlogd.service,0755',
    'virtlogd,/usr/sbin/virtlogd,0,system.slice,virtlogd.service,0755',
    'whiptail,/usr/bin/whiptail,0,user.slice,user-1000.slice,0755',
    'wpa_supplicant,/usr/bin/wpa_supplicant,0,system.slice,wpa_supplicant.service,0755',
    'wpa_supplicant,/usr/sbin/wpa_supplicant,0,system.slice,wpa_supplicant.service,0755',
    'X,/nix/store/__VERSION__/bin/Xorg,0,system.slice,display-manager.service,0555',
    'xdg-desktop-por,/usr/libexec/xdg-desktop-portal,0,user.slice,user-1000.slice,0755',
    'xdg-desktop-por,/usr/libexec/xdg-desktop-portal-gnome,0,user.slice,user-1000.slice,0755',
    'xdg-desktop-por,/usr/libexec/xdg-desktop-portal-gtk,0,user.slice,user-1000.slice,0755',
    'xdg-document-po,/usr/libexec/xdg-document-portal,0,user.slice,user-1000.slice,0755',
    'xdg-permission-,/usr/libexec/xdg-permission-store,0,user.slice,user-0.slice,0755',
    'xdg-permission-,/usr/libexec/xdg-permission-store,0,user.slice,user-1000.slice,0755',
    'Xorg,/usr/lib/Xorg,0,system.slice,lightdm.service,0755',
    'Xorg,/usr/lib/Xorg,0,system.slice,sddm.service,0755',
    'Xorg,/usr/lib/xorg/Xorg,0,system.slice,lightdm.service,0755',
    'Xorg,/usr/lib/xorg/Xorg,0,system.slice,sddm.service,0755',
    'yum,/usr/bin/python__VERSION__,0,user.slice,user-1000.slice,0755',
    'zed,/nix/store/__VERSION__/bin/zed,0,system.slice,zfs-zed.service,0555',
    'zed,/usr/sbin/zed,0,system.slice,zfs-zed.service,0755',
    'zfs,/nix/store/__VERSION__/bin/zfs,0,system.slice,zfs-snapshot-frequent.service,0555',
    'zfs,/nix/store/__VERSION__/bin/zfs,0,system.slice,zfs-snapshot-hourly.service,0555',
    'zfs,/nix/store/__VERSION__/bin/zfs,0,system.slice,znapzend.service,0555',
    'zfs-auto-snapsh,/nix/store/__VERSION__/bin/ruby,0,system.slice,zfs-snapshot-frequent.service,0555',
    'zfs-auto-snapsh,/nix/store/__VERSION__/bin/ruby,0,system.slice,zfs-snapshot-hourly.service,0555'
  )
  AND NOT exception_key LIKE 'incusd,/usr/libexec/incus/incusd,0,lxc.monitor.%,,0755'
  AND NOT exception_key LIKE 'dhcpcd,/usr/sbin/dhcpcd,0,system.slice,ifup@en%.service,0755'
  AND NOT exception_key LIKE '%beat,%/opt/Elastic/Agent/data/elastic-%/components/%beat,0,system.slice,elastic-agent.service,%'
  AND NOT exception_key LIKE 'abrt-dbus,/usr/sbin/abrt-dbus,0,system.slice,system-dbus%org.freedesktop.problems.slice,%'
  AND NOT exception_key LIKE 'containerd,/var/lib/rancher/k3s/data/%/bin/k3s,0,system.slice,k3s.service,0755'
  AND NOT exception_key LIKE 'containerd-shim,/var/lib/rancher/k3s/data/%/bin/containerd-shim-runc-v2,0,system.slice,k3s.service,0755'
  AND NOT exception_key LIKE 'elastic-agent,%/opt/Elastic/Agent/data/elastic-agent%/elastic-agent,0,system.slice,elastic-agent.service,%'
  AND NOT exception_key LIKE 'fusermount3,/usr/bin/fusermount3,%,user.slice,user-%.slice,4755'
  AND NOT exception_key LIKE 'incusd,%/bin/incusd,0,lxc.monitor.%,,0755'
  AND NOT exception_key LIKE 'k3s-server,/var/lib/rancher/k3s/data/%/bin/k3s,0,system.slice,k3s.service,0755'
  AND NOT exception_key LIKE 'osquery-extensi,/opt/Elastic/Agent/data/elastic-agent-%/components/osquery-extension.ext,0,system.slice,elastic-agent.service,0750'
  AND NOT exception_key LIKE 'osqueryd,/opt/Elastic/Agent/data/elastic-agent-%/components/osqueryd,0,system.slice,elastic-agent.service,0750'
  AND NOT exception_key LIKE 'server,/var/lib/rancher/k3s/data/%/bin/k3s,0,system.slice,k3s.service,0755'
  AND NOT exception_key LIKE 'tuned-ppd,/usr/bin/python3.%,system.slice,tuned-ppd.service,0755'
  AND NOT p0.path IN ('/bin/bash', '/usr/bin/bash')
  AND NOT p0.cgroup_path LIKE '/kubepods.slice/kubepods-%'
  AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  p0.pid
