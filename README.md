# Sysrepo Firmware plugin (DT)

## Introduction

This Sysrepo plugin is responsible for upgrading OpenWrt-compatible systems via the [**sysupgrade**](https://openwrt.org/docs/techref/sysupgrade) using the Sysrepo/YANG datastore configuration.

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/firmware-plugin

$ rm -rf ./build && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/firmware-plugin/build

$ make && make install
[...]
[ 75%] Building C object CMakeFiles/sysrepo-plugin-dt-firmware.dir/src/utils/memory.c.o
[100%] Linking C executable sysrepo-plugin-dt-firmware
[100%] Built target sysrepo-plugin-dt-firmware
[100%] Built target sysrepo-plugin-dt-firmware

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/firmware-plugin

$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i ./yang/ietf-netconf-acm@2018-02-14.yang
$ sysrepoctl -i ./yang/iana-crypt-hash@2014-08-06.yang
$ sysrepoctl -i ./yang/ietf-system@2014-08-06.yang
$ sysrepoctl -i ./yang/terastream-software@2017-11-01.yang
```

## YANG Overview

The `terastream-software` YANG module with the `ts-sw` prefix inherits and extends the `ietf-system` YANG module which consists of the following `container` paths:

* `/ietf-system:system` — system group configuration data
* `/ietf-system:system/terastream-software:software` — augment for system configuration data
	* (+) containers: `download-policy`, `upgrade-policy`, ...
	* (+) lists: `software`, ...

The following items are not configurational i.e. they are `operational` state data:

* `/ietf-system:system-state` — system group operational state data
* `/ietf-system:system-state/terastream-software:*` — augments for system operational data
	* (+) leafs: `running-software`, ...
	* (+) lists: `software`, ...
* `/ietf-system:system-state/platform/terastream-software:*` — augments for system operational data
	* (+) leafs: `software-version`, `serial-number`, ...

This plugin also exposes following items as RPC paths:

* `/ietf-system:system-restart` — RPC call for system reboot
* `/ietf-system:system-shutdown` — RPC call for system shutdown
* `/terastream-software:system-reset-restart` — RPC call for system reset and restart


## Running and Examples

This plugin is installed as the `sysrepo-plugin-dt-firmware` binary to `${SYSREPO_DIR}/bin/` directory path. Before executing the plugin binary it is necessary to initialize the datastore with appropriate example data:

```
$ sysrepocfg -f xml -C ./example/router_sysupgrade.xml -d startup -m 'ietf-system'
$ sysrepocfg -f xml -C ./example/router_sysupgrade.xml -d running -m 'ietf-system'
```

After loading the example simply invoke this binary, making sure that the environment variables are set correctly:

```
$ sysrepo-plugin-dt-firmware
[...]
[INF]: Applying scheduled changes.
[INF]: No scheduled changes.
[INF]: Session 4 (user "...") created.
[INF]: plugin: start session to startup datastore
[INF]: Session 5 (user "...") created.
[INF]: plugin: subscribing to module change
[INF]: plugin: subscribing to get oper items
[INF]: plugin: subscribing to rpc
[INF]: plugin: plugin init done
[...]
```

Output from the plugin is expected; the plugin has been initialized with `startup` and `running` datastore contents at `${SYSREPO_DIR}/etc/sysrepo`. We can confirm the contents present in Sysrepo by invoking the following command:

```
$ sysrepocfg -X -d startup -f json -m 'ietf-system'
{
  "ietf-system:system": {
    "terastream-software:software": {
      "download-policy": {
        "download-attempts": 32
      },
      "software": [
        {
          "source": "http://192.168.1.215:8000/EG400-WU21U_PANTERA-DEV3.13.1-171108_1417.y2",
          "checksum": {
            "type": "sha-256",
            "value": "ac3dbaa85000103e107c0f353e82de00680ecce0e0495fc4ca6711020100b8ba"
          },
          "preserve-configuration": true
        }
      ]
    }
  }
}
```

Operational state data, as defined by the `terastream-software` module can be accessed as usual:

```
$ sysrepocfg -X -d operational -f json -x '/ietf-system:system-state/platform/terastream-software:serial-number'
{
  "ietf-system:system-state": {
    "platform": {
      "terastream-software:serial-number": "EG4024H179041692"
    }
  }
}
```

Additionally, this plugin handles various RPC paths. For instance, invoking the following exampleaction will trigger a reboot of the device:

```
$ sysrepocfg --rpc=./example/reset.xml -m 'ietf-system'
```

This action is followed by output on the plugin standard output:

```
[...]
[INF]: Processing "/ietf-system:system-restart" "rpc" event with ID 1 priority 0 (remaining 1 subscribers).
[DBG]: plugin: firmware_rpc_cb: child in 229743
[INF]: Successful processing of "rpc" event with ID 1 priority 0 (remaining 0 subscribers).
[...]
```