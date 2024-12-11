# securitykernelmodule
Kernel module drops income/outcome  packets  containing security options. 


## Buolding

```
make
```
Result:
```
Makefile  modules.order  Module.symvers  README.md  skm.c  skm.ko  skm.mod  skm.mod.c  skm.mod.o  skm.o  ysend.py
```

## Installation

```
sudo insmod ./skm.ko
```

## Deinstallation 
```
sudo rmmod ./skm.ko
```

## Log messages check
```
sudo dmesg
```

## Testing
### Incoming packets drop check
Install kernel module *skm.ko* to PC under test.

Copy scapy script *ysend.py* to a remote PC an change in script IP address ( in substring dst='192.168.56.134') to IP of PC under test. Run script:
```
sudo python3 ysend.py
```

Check that log messages on PC under test contains messages like:

```
Security filter packet has security options, dropped.
```
