-- Unexpected systemd units, may be evidence of persistence
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/002/ (Create or Modify System Process: Systemd Service)
--
-- false positives:
--   * System updates
--
-- tags: persistent seldom filesystem systemd
-- platform: linux
SELECT --  description AS 'desc',
  fragment_path AS path,
  MAX(user, 'root') AS effective_user,
  following,
  hash.sha256,
  file.ctime,
  file.size,
  CONCAT (id, ',', description, ',', user) AS exception_key
FROM
  systemd_units
  LEFT JOIN hash ON systemd_units.fragment_path = hash.path
  LEFT JOIN file ON systemd_units.fragment_path = file.path
WHERE
  active_state != 'inactive'
  AND sub_state != 'plugged'
  AND sub_state != 'mounted'
  AND file.filename != ''
  -- Don't care about logical groupings.
  AND NOT file.filename LIKE '%.target'
  -- All of these are known good exceptions in known good paths
  AND NOT (
    (
      -- Only allow fragment paths in known good directories
      fragment_path LIKE '/lib/systemd/system/%'
      OR fragment_path LIKE '/usr/lib/systemd/system/%'
      OR fragment_path LIKE '/etc/systemd/system/%'
      OR fragment_path LIKE '/run/systemd/generator/%'
      OR fragment_path LIKE '/run/systemd/generator.late/%.service'
      OR fragment_path LIKE '/run/systemd/transient/%'
    )
    AND (
      exception_key IN (
        '-.slice,Root Slice,',
        'ModemManager.service,Modem Manager,root',
        'NetworkManager-dispatcher.service,Network Manager Script Dispatcher Service,',
        'NetworkManager-wait-online.service,Network Manager Wait Online,',
        'NetworkManager.service,Network Manager,',
        'abrt-journal-core.service,ABRT coredumpctl message creator,',
        'abrt-journal-core.service,Creates ABRT problems from coredumpctl messages,',
        'abrt-oops.service,ABRT kernel log watcher,',
        'abrt-xorg.service,ABRT Xorg log watcher,',
        'abrtd.service,ABRT Automated Bug Reporting Tool,',
        'abrtd.service,ABRT Daemon,',
        'accounts-daemon.service,Accounts Service,',
        'acpid.path,ACPI Events Check,',
        'acpid.service,ACPI Daemon,',
        'acpid.service,ACPI event daemon,',
        'acpid.socket,ACPID Listen Socket,',
        'akmods.service,Builds and install new kmods from akmod packages,',
        'alsa-restore.service,Save/Restore Sound Card State,',
        'alsa-state.service,Manage Sound Card State (restore and store),',
        'alsa-store.service,Store Sound Card State,',
        'anacron.service,Run anacron jobs,',
        'anacron.timer,Trigger anacron every hour,',
        'apcupsd.service,APC UPS Power Control Daemon for Linux,',
        'apparmor.service,Load AppArmor profiles,',
        'apport-autoreport.path,Process error reports when automatic reporting is enabled (file watch),',
        'apport-autoreport.timer,Process error reports when automatic reporting is enabled (timer based),',
        'apport.service,LSB: automatic crash report generation,',
        'apt-daily-upgrade.timer,Daily apt upgrade and clean activities,',
        'apt-daily.service,Daily apt download activities,',
        'apt-daily.timer,Daily apt download activities,',
        'archlinux-keyring-wkd-sync.service,Refresh existing keys of archlinux-keyring,',
        'archlinux-keyring-wkd-sync.timer,Refresh existing PGP keys of archlinux-keyring regularly,',
        'atd.service,Deferred execution scheduler,',
        'audit.service,Kernel Auditing,',
        'auditd.service,Security Auditing Service,',
        'avahi-daemon.service,Avahi mDNS/DNS-SD Stack,',
        'avahi-daemon.socket,Avahi mDNS/DNS-SD Stack Activation Socket,',
        'binfmt-support.service,Enable support for additional executable binary formats,',
        'blk-availability.service,Availability of block devices,',
        'bluetooth.service,Bluetooth service,',
        'bolt.service,Thunderbolt system service,',
        'chrony.service,chrony, an NTP client/server',
        'chronyd.service,NTP client/server,',
        'cloud-config.service,Apply the settings specified in cloud-config,',
        'cloud-final.service,Execute cloud user/final scripts,',
        'cloud-init-hotplugd.socket,cloud-init hotplug hook socket,',
        'cloud-init-local.service,Initial cloud-init job (pre-networking),',
        'cloud-init.service,Initial cloud-init job (metadata service crawler),',
        'colord.service,Manage, Install and Generate Color Profiles,colord',
        'com.system76.PowerDaemon.service,System76 Power Daemon,',
        'com.system76.Scheduler.service,Automatically configure CPU scheduler for responsiveness on AC,',
        'console-setup.service,Set console font and keymap,',
        'containerd.service,containerd container runtime,',
        'cron.service,Regular background program processing daemon,',
        'crond.service,Command Scheduler,',
        'cronie.service,Periodic Command Scheduler,',
        'cups-browsed.service,Make remote CUPS printers available locally,',
        'cups.path,CUPS Scheduler,',
        'cups.service,CUPS Scheduler,',
        'cups.socket,CUPS Scheduler,',
        'dbus-:1.2-org.pop_os.transition_system@0.service,dbus-:1.2-org.pop_os.transition_system@0.service,0',
        'dbus-broker.service,D-Bus System Message Bus,',
        'dbus.service,D-Bus System Message Bus,',
        'dbus.socket,D-Bus System Message Bus Socket,',
        'dhcpcd.service,DHCP Client,',
        'display-manager.service,X11 Server,',
        'dkms.service,Builds and install new kernel modules through DKMS,',
        'dm-event.socket,Device-mapper event daemon FIFOs,',
        'dnf-automatic-install.service,dnf automatic install updates,',
        'dnf-automatic-install.timer,dnf-automatic-install timer,',
        'dnf-makecache.service,dnf makecache,',
        'dnf-makecache.timer,dnf makecache --timer,',
        'docker.service,Docker Application Container Engine,',
        'docker.socket,Docker Socket for the API,',
        'dpkg-db-backup.timer,Daily dpkg database backup timer,',
        'dracut-shutdown.service,Restore /run/initramfs on shutdown,',
        'e2scrub_all.timer,Periodic ext4 Online Metadata Check for All Filesystems,',
        'finalrd.service,Create final runtime dir for shutdown pivot root,',
        'firewall.service,Firewall,',
        'firewalld.service,firewalld - dynamic firewall daemon,',
        'flatpak-system-helper.service,flatpak system helper,',
        'fprintd.service,Fingerprint Authentication Daemon,',
        'fstrim.service,Discard unused blocks on filesystems from /etc/fstab,',
        'fstrim.timer,Discard unused blocks once a week,',
        'fstrim.timer,Discard unused filesystem blocks once a week,',
        'fwupd-refresh.service,Refresh fwupd metadata and update motd,fwupd-refresh',
        'fwupd-refresh.timer,Refresh fwupd metadata regularly,',
        'fwupd.service,Firmware update daemon,',
        'gdm.service,GNOME Display Manager,',
        'geoclue.service,Location Lookup Service,geoclue',
        'gitsign.service,Keyless Git signing with Sigstore!,',
        'gssproxy.service,GSSAPI Proxy Daemon,',
        'haproxy.service,HAProxy Load Balancer,',
        'ifupdown-pre.service,Helper to synchronize boot up for ifupdown,',
        'iio-sensor-proxy.service,IIO Sensor Proxy service,',
        'import-state.service,Import network configuration from initramfs,',
        'irqbalance.service,irqbalance daemon,',
        'iscsid.socket,Open-iSCSI iscsid Socket,',
        'iscsiuio.socket,Open-iSCSI iscsiuio Socket,',
        'iwd.service,Wireless service,',
        'kerneloops.service,Tool to automatically collect and submit kernel crash signatures,kernoops',
        'keyboard-setup.service,Set the console keyboard layout,',
        'kmod-static-nodes.service,Create List of Static Device Nodes,',
        'kmod-static-nodes.service,Create list of static device nodes for the current kernel,',
        'kolide-launcher.service,Kolide launcher,',
        'launcher.kolide-k2.service,The Kolide Launcher,',
        'ldconfig.service,Rebuild Dynamic Linker Cache,',
        'libvirtd-admin.socket,Libvirt admin socket,',
        'libvirtd-ro.socket,Libvirt local read-only socket,',
        'libvirtd.service,Virtualization daemon,',
        'libvirtd.socket,Libvirt local socket,',
        'lightdm.service,Light Display Manager,',
        'lima-guestagent.service,lima-guestagent,',
        'livesys-late.service,SYSV: Late init script for live image.,',
        'livesys.service,LSB: Init script for live image.,',
        'lm-sensors.service,Initialize hardware monitoring sensors,',
        'lm_sensors.service,Hardware Monitoring Sensors,',
        'lm_sensors.service,Initialize hardware monitoring sensors,',
        'logrotate-checkconf.service,Logrotate configuration check,',
        'logrotate.timer,Daily rotation of log files,',
        'logrotate.timer,logrotate.timer,',
        'low-memory-monitor.service,Low Memory Monitor,',
        'lvm2-lvmpolld.socket,LVM2 poll daemon socket,',
        'lvm2-monitor.service,Monitoring of LVM2 mirrors, snapshots etc. using dmeventd or progress polling,',
        'machine.slice,Virtual Machine and Container Slice,',
        'man-db.service,Daily man-db regeneration,root',
        'man-db.timer,Daily man-db regeneration,',
        'mcelog.service,Machine Check Exception Logging Daemon,',
        'mlocate-updatedb.timer,Updates mlocate database every day,',
        'modprobe@efi_pstore.service,Load Kernel Module efi_pstore,',
        'modprobe@pstore_blk.service,Load Kernel Module pstore_blk,',
        'modprobe@pstore_zone.service,Load Kernel Module pstore_zone,',
        'modprobe@ramoops.service,Load Kernel Module ramoops,',
        'monitorix.service,Monitorix,',
        'motd-news.timer,Message of the Day,',
        'mount-pstore.service,mount-pstore.service,',
        'multipathd.service,Device-Mapper Multipath Device Controller,',
        'multipathd.socket,multipathd control socket,',
        'nessusd.service,The Nessus Vulnerability Scanner,',
        'netcf-transaction.service,Rollback uncommitted netcf network config change transactions,',
        'network-local-commands.service,Extra networking commands.,',
        'network-setup.service,Networking Setup,',
        'networkd-dispatcher.service,Dispatcher daemon for systemd-networkd,',
        'networking.service,Raise network interfaces,',
        'nginx.service,Nginx Web Server,nginx',
        'nix-daemon.service,Nix Daemon,',
        'nix-daemon.socket,Nix Daemon Socket,',
        'nix-gc.timer,nix-gc.timer,',
        'nscd.service,Name Service Cache Daemon (nsncd),nscd',
        'nscd.service,Name Service Cache Daemon,nscd',
        'nvidia-fallback.service,Fallback to nouveau as nvidia did not load,',
        'nvidia-persistenced.service,NVIDIA Persistence Daemon,',
        'nvidia-powerd.service,nvidia-powerd service,',
        'nvidia-suspend.service,NVIDIA system suspend actions,',
        'openvpn.service,OpenVPN service,',
        'orbit,/opt/orbit/bin/orbit/linux/stable/orbit,0',
        'orbit.service,Orbit osquery,',
        'packagekit.service,PackageKit Daemon,root',
        'pcscd.service,PC/SC Smart Card Daemon,',
        'pcscd.socket,PC/SC Smart Card Daemon Activation Socket,',
        'phpsessionclean.timer,Clean PHP session files every 30 mins,',
        'plocate-updatedb.service,Update the plocate database,',
        'plocate-updatedb.timer,Update the plocate database daily,',
        'plymouth-quit-wait.service,Hold until boot process finishes up,',
        'plymouth-quit.service,Terminate Plymouth Boot Screen,',
        'plymouth-read-write.service,Tell Plymouth To Write Out Runtime Data,',
        'plymouth-start.service,Show Plymouth Boot Screen,',
        'polkit.service,Authorization Manager,',
        'polkit.service,Authorization Manager,polkitd',
        'power-profiles-daemon.service,Power Profiles daemon,',
        'proc-sys-fs-binfmt_misc.automount,Arbitrary Executable File Formats File System Automount Point,',
        'pwrstatd.service,The monitor UPS software.,',
        'qemu-kvm.service,QEMU KVM preparation - module, ksm, hugepages,',
        'qualys-cloud-agent.service,Qualys cloud agent daemon,',
        'raid-check.timer,Weekly RAID setup health check,',
        'realmd.service,Realm and Domain Configuration,',
        'reflector.service,Refresh Pacman mirrorlist with Reflector.,',
        'reflector.timer,Refresh Pacman mirrorlist weekly with Reflector.,',
        'reload-systemd-vconsole-setup.service,Reset console on configuration changes,',
        'resolvconf-pull-resolved.path,resolvconf-pull-resolved.path,',
        'resolvconf.service,Nameserver information manager,',
        'resolvconf.service,resolvconf update,',
        'rngd.service,Hardware RNG Entropy Gatherer Daemon,',
        'rpc-statd-notify.service,Notify NFS peers of a restart,',
        'rsyslog.service,System Logging Service,',
        'rtkit-daemon.service,RealtimeKit Scheduling Policy Service,',
        'sddm.service,Simple Desktop Display Manager,',
        'serial-getty@ttyS0.service,Serial Getty on ttyS0,',
        'setroubleshootd.service,SETroubleshoot daemon for processing new SELinux denial logs,setroubleshoot',
        'setvtrgb.service,Set console scheme,',
        'shadow.service,Verify integrity of password and group files,',
        'shadow.timer,Daily verification of password and group files,',
        'smartd.service,Self Monitoring and Reporting Technology (SMART) Daemon,',
        'snap.lxd.daemon.unix.socket,Socket unix for snap application lxd.daemon,',
        'snap.lxd.user-daemon.unix.socket,Socket unix for snap application lxd.user-daemon,',
        'snap.yubioath-desktop.pcscd.service,Service for snap application yubioath-desktop.pcscd,',
        'snapd.apparmor.service,Load AppArmor profiles managed internally by snapd,',
        'snapd.seeded.service,Wait until snapd is fully seeded,',
        'snapd.service,Snap Daemon,',
        'snapd.socket,Socket activation for snappy daemon,',
        'ssh.service,OpenBSD Secure Shell server,',
        'sshd.service,OpenSSH Daemon,',
        'sshd.service,OpenSSH server daemon,',
        'sshd.service,SSH Daemon,',
        'sssd-kcm.service,SSSD Kerberos Cache Manager,',
        'sssd-kcm.socket,SSSD Kerberos Cache Manager responder socket,',
        'supergfxd.service,SUPERGFX,',
        'switcheroo-control.service,Switcheroo Control Proxy service,',
        'syslog.socket,Syslog Socket,',
        'sysstat-collect.timer,Run system activity accounting tool every 10 minutes,',
        'sysstat-summary.timer,Generate summary of yesterday''s process accounting,',
        'sysstat.service,Resets System Activity Logs,root',
        'system.slice,System Slice,',
        'systemd-ask-password-console.path,Dispatch Password Requests to Console Directory Watch,',
        'systemd-ask-password-plymouth.path,Forward Password Requests to Plymouth Directory Watch,',
        'systemd-ask-password-wall.path,Forward Password Requests to Wall Directory Watch,',
        'systemd-binfmt.service,Set Up Additional Binary Formats,',
        'systemd-boot-random-seed.service,Update Boot Loader Random Seed,',
        'systemd-boot-update.service,Automatic Boot Loader Update,',
        'systemd-coredump.socket,Process Core Dump Socket,',
        'systemd-cryptsetup@cryptdata.service,Cryptography Setup for cryptdata,',
        'systemd-cryptsetup@cryptoswap.service,Cryptography Setup for cryptoswap,',
        'systemd-cryptsetup@cryptswap.service,Cryptography Setup for cryptswap,',
        'systemd-fsck-root.service,File System Check on Root Device,',
        'systemd-fsckd.socket,fsck to fsckd communication Socket,',
        'systemd-growfs@-.service,Grow File System on /,',
        'systemd-homed-activate.service,Home Area Activation,',
        'systemd-homed.service,Home Area Manager,',
        'systemd-hostnamed.service,Hostname Service,',
        'systemd-hwdb-update.service,Rebuild Hardware Database,',
        'systemd-initctl.socket,initctl Compatibility Named Pipe,',
        'systemd-journal-catalog-update.service,Rebuild Journal Catalog,',
        'systemd-journal-flush.service,Flush Journal to Persistent Storage,',
        'systemd-journald-audit.socket,Journal Audit Socket,',
        'systemd-journald-dev-log.socket,Journal Socket (/dev/log),',
        'systemd-journald.service,Journal Service,',
        'systemd-journald.socket,Journal Socket,',
        'systemd-localed.service,Locale Service,',
        'systemd-logind.service,User Login Management,',
        'systemd-machined.service,Virtual Machine and Container Registration Service,',
        'systemd-modules-load.service,Load Kernel Modules,',
        'systemd-network-generator.service,Generate network units from Kernel command line,',
        'systemd-networkd-wait-online.service,Wait for Network to be Configured,',
        'systemd-networkd.service,Network Configuration,systemd-network',
        'systemd-networkd.socket,Network Service Netlink Socket,',
        'systemd-oomd.service,Userspace Out-Of-Memory (OOM) Killer,systemd-oom',
        'systemd-oomd.socket,Userspace Out-Of-Memory (OOM) Killer Socket,',
        'systemd-pcrmachine.service,TPM2 PCR Machine ID Measurement,',
        'systemd-pcrphase-sysinit.service,TPM2 PCR Barrier (Initialization),',
        'systemd-pcrphase.service,TPM2 PCR Barrier (User),',
        'systemd-random-seed.service,Load/Save OS Random Seed,',
        'systemd-random-seed.service,Load/Save Random Seed,',
        'systemd-remount-fs.service,Remount Root and Kernel File Systems,',
        'systemd-resolved.service,Network Name Resolution,systemd-resolve',
        'systemd-rfkill.socket,Load/Save RF Kill Switch Status /dev/rfkill Watch,',
        'systemd-suspend.service,System Suspend,',
        'systemd-sysctl.service,Apply Kernel Variables,',
        'systemd-sysusers.service,Create System Users,',
        'systemd-timedated.service,Time & Date Service,',
        'systemd-timesyncd.service,Network Time Synchronization,systemd-timesync',
        'systemd-tmpfiles-clean.timer,Daily Cleanup of Temporary Directories,',
        'systemd-tmpfiles-setup-dev.service,Create Static Device Nodes in /dev,',
        'systemd-tmpfiles-setup.service,Create Volatile Files and Directories,',
        'systemd-udev-settle.service,Wait for udev To Complete Device Initialization,',
        'systemd-udev-trigger.service,Coldplug All udev Devices,',
        'systemd-udevd-control.socket,udev Control Socket,',
        'systemd-udevd-kernel.socket,udev Kernel Socket,',
        'systemd-udevd.service,Rule-based Manager for Device Events and Files,',
        'systemd-update-done.service,Update is Completed,',
        'systemd-update-utmp.service,Record System Boot/Shutdown in UTMP,',
        'systemd-update-utmp.service,Update UTMP about System Boot/Shutdown,',
        'systemd-user-sessions.service,Permit User Sessions,',
        'systemd-userdbd.service,User Database Manager,',
        'systemd-userdbd.socket,User Database Manager Socket,',
        'systemd-vconsole-setup.service,Setup Virtual Console,',
        'systemd-vconsole-setup.service,Virtual Console Setup,',
        'tailscaled.service,Tailscale node agent,',
        'thermald.service,Thermal Daemon Service,',
        'tlp.service,TLP system startup/shutdown,',
        'touchegg.service,Touchégg Daemon,',
        'ua-timer.timer,Ubuntu Advantage Timer for running repeated jobs,',
        'udisks2.service,Disk Manager,',
        'ufw.service,Uncomplicated firewall,',
        'unattended-upgrades.service,Unattended Upgrades Shutdown,',
        'unbound-anchor.timer,daily update of the root trust anchor for DNSSEC,',
        'update-notifier-download.timer,Download data for packages that failed at package install time,',
        'update-notifier-motd.timer,Check to see whether there is a new version of Ubuntu available,',
        'updatedb.timer,Daily locate database update,',
        'upower.service,Daemon for power management,',
        'uresourced.service,User resource assignment daemon,',
        'usbmuxd.service,Socket daemon for the usbmux protocol used by Apple devices,',
        'user.slice,User and Session Slice,',
        'uuidd.socket,UUID daemon activation socket,',
        'vboxautostart-service.service,vboxautostart-service.service,',
        'vboxballoonctrl-service.service,vboxballoonctrl-service.service,',
        'vboxdrv.service,VirtualBox Linux kernel module,',
        'vboxweb-service.service,vboxweb-service.service,',
        'velociraptor_client.service,Velociraptor linux client,',
        'velociraptor_server.service,Velociraptor server,velociraptor',
        'virtinterfaced.socket,Libvirt interface local socket,',
        'virtlockd.socket,Virtual machine lock manager socket,',
        'virtlogd-admin.socket,Virtual machine log manager socket,',
        'virtlogd.service,Virtual machine log manager,',
        'virtlogd.socket,Virtual machine log manager socket,',
        'virtnetworkd.socket,Libvirt network local socket,',
        'virtnodedevd.socket,Libvirt nodedev local socket,',
        'virtnwfilterd.socket,Libvirt nwfilter local socket,',
        'virtproxyd.socket,Libvirt proxy local socket,',
        'virtqemud-admin.socket,Libvirt qemu admin socket,',
        'virtqemud-ro.socket,Libvirt qemu local read-only socket,',
        'virtqemud.service,Virtualization qemu daemon,',
        'virtqemud.socket,Libvirt qemu local socket,',
        'virtsecretd.socket,Libvirt secret local socket,',
        'virtstoraged.socket,Libvirt storage local socket,',
        'whoopsie.path,Start whoopsie on modification of the /var/crash directory,',
        'wpa_supplicant.service,WPA supplicant,',
        'zfs-import-cache.service,Import ZFS pools by cache file,',
        'zfs-load-key-rpool.service,Load ZFS key for rpool,',
        'zfs-load-module.service,Install ZFS kernel module,',
        'zfs-mount.service,Mount ZFS filesystems,',
        'zfs-scrub.service,ZFS pools scrubbing,',
        'zfs-scrub.timer,zfs-scrub.timer,',
        'zfs-share.service,ZFS file system shares,',
        'zfs-snapshot-daily.service,ZFS auto-snapshotting every day,',
        'zfs-snapshot-frequent.service,ZFS auto-snapshotting every 15 mins,',
        'zfs-snapshot-hourly.service,ZFS auto-snapshotting every hour,',
        'zfs-volume-wait.service,Wait for ZFS Volume (zvol) links in /dev,',
        'zfs-zed.service,ZFS Event Daemon (zed),',
        'znapzend.service,ZnapZend - ZFS Backup System,root',
        'zpool-trim.service,ZFS pools trim,',
        'zpool-trim.timer,zpool-trim.timer,'
      )
      OR exception_key LIKE 'machine-qemu%.scope,Virtual Machine qemu%,'
      OR exception_key LIKE 'zfs-snapshot-%.timer,zfs-snapshot-%.timer,'
      OR exception_key LIKE 'systemd-cryptsetup@dm_crypt%.service,Cryptography Setup for dm_crypt-%,'
      OR exception_key LIKE 'zfs-snapshot-%.service,zfs-snapshot-%.service,'
      OR exception_key LIKE 'dbus-:1.%-org.freedesktop.problems@%.service,dbus-:%.%-org.freedesktop.problems@%.service,0'
      OR exception_key LIKE 'run-media-%.mount,run-media-%.mount,'
      OR id LIKE ''
      OR id LIKE 'dev-disk-by%.swap'
      OR id LIKE 'dev-mapper-%.swap'
      OR id LIKE 'dev-zram%.swap'
      OR id LIKE 'docker-%.scope'
      OR id LIKE 'getty@tty%.service'
      OR id LIKE 'home-manager-%.service'
      OR id LIKE 'lvm2-pvscan@%.service'
      OR id LIKE 'session-%.scope'
      OR id LIKE 'system-systemd%cryptsetup.slice'
      OR id LIKE 'systemd-backlight@%.service'
      OR id LIKE 'systemd-cryptsetup@luks%.service'
      OR id LIKE 'systemd-cryptsetup@nvme%.service'
      OR id LIKE 'systemd-fsck@dev-disk-by%service'
      OR id LIKE 'systemd-zram-setup@zram%.service'
      OR id LIKE 'user-runtime-dir@%.service'
      OR id LIKE 'user@%.service'
      OR id LIKE 'akmods@%64.service'
    )
  )
