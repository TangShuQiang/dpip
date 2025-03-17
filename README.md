# dpp-基于DPDK的TCP/IP用户态协议栈
## 1. 环境配置：Ubuntu18.04+DPDK19.08.2
### 1.1 虚拟机配置两块网卡：桥接网卡（DPDK运行的网卡），NAT网卡（ssh连接的网卡）；
### 1.2 关机，修改网卡配置信息(Windows下虚拟机安装文件xxx.vmx)，以支持多队列网卡；
```C++
# 将ethernet0.virtualDev由e1000修改为vmxnet3
ethernet0.virtualDev = "vmxnet3"
ethernet0.wakeOnPcktRcv = "TRUE"
```
### 1.3 开机，修改Ubuntu系统的启动参数
```shell
shell> sudo vim /etc/default/grub
# net.ifnames=0 biosdevname=0,使得网卡名称从0开始命名
GRUB_CMDLINE_LINUX="find_preseed=/preseed.cfg noprompt net.ifnames=0 biosdevname=0 default_hugepagesz=1G hugepagesz=2M hugepages=1024 isolcpus=0-2"

shell> sudo update-grub
shell> sudo reboot
```
### 1.4 查看系统是否支持多队列网卡
```shell
shell> cat /proc/interrupts | grep eth0
  56:          0          0          0          0          0       1099          0      10330  PCI-MSIX-0000:03:00.0    0-edge      eth0-rxtx-0
  57:          0          0          0         16          0          0        106          0  PCI-MSIX-0000:03:00.0    1-edge      eth0-rxtx-1
  58:          0          0          0          0       6781          0          0        471  PCI-MSIX-0000:03:00.0    2-edge      eth0-rxtx-2
  59:        115          0          0         88          0          0          0          0  PCI-MSIX-0000:03:00.0    3-edge      eth0-rxtx-3
  60:          0        172          0          0          0          0         62          0  PCI-MSIX-0000:03:00.0    4-edge      eth0-rxtx-4
  61:          0          0        159         52          0          0          0          0  PCI-MSIX-0000:03:00.0    5-edge      eth0-rxtx-5
  62:          0          0          0         90          0         29          0          0  PCI-MSIX-0000:03:00.0    6-edge      eth0-rxtx-6
  63:          0          0          0        395         86          0          0          0  PCI-MSIX-0000:03:00.0    7-edge      eth0-rxtx-7
  64:          0          0          0          0          0          0          0          0  PCI-MSIX-0000:03:00.0    8-edge      eth0-event-8 
```
### 1.5 下载编译DPDK
```shell
shell> sudo apt install gcc make numactl libnuma-dev

shell> wget https://fast.dpdk.org/rel/dpdk-19.08.2.tar.xz
shell> tar -xvf dpdk-19.08.2.tar.xz
shell> cd dpdk-stable-19.08.2/

shell> ./usertools/dpdk-setup.sh   
shell> 39 # 选择 x86_64-native-linux-gcc
```
### 1.6 配置DPDK的环境变量
```shell
shell> vim ~/.bashrc    # 加上下面两行环境变量设置
export RTE_SDK=/home/tang/workspace/dpip/dpdk-stable-19.08.2
export RTE_TARGET=x86_64-native-linux-gcc

shell> source ~/.bashrc
```
### 1.7 记录桥接网卡（DPDK运行的网卡）的信息
```shell
shell> ifconfig     # 记录下IP（114.213.212.113）和MAC（00:0c:29:8c:0b:25）
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 114.213.212.113  netmask 255.255.255.0  broadcast 114.213.212.255
        inet6 2001:da8:d805:c308:279b:8c1b:e4e3:d151  prefixlen 64  scopeid 0x0<global>
        inet6 2001:da8:d805:3180:3307:38a5:487d:141e  prefixlen 64  scopeid 0x0<global>
        inet6 2001:da8:d805:3180::17:1e3a  prefixlen 128  scopeid 0x0<global>
        inet6 2001:da8:d805:c308:e175:5ee7:f2f7:fbe0  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::69c5:5dcf:fa57:7432  prefixlen 64  scopeid 0x20<link>
        inet6 2001:da8:d805:3180:e175:5ee7:f2f7:fbe0  prefixlen 64  scopeid 0x0<global>
        ether 00:0c:29:8c:0b:25  txqueuelen 1000  (Ethernet)
        RX packets 844  bytes 494309 (494.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 361  bytes 71456 (71.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
### 1.8 DPDK接管网卡
```shell
shell> sudo ifconfig eth0 down

shell> ./usertools/dpdk-setup.sh 

shell> 43 		# 插入 IGB_UIO 模块， 选择网卡为 vmxnet3 会加载此模块

shell> 44 		# 插入 VFIO 模块，选择网卡为 e1000 会加载此模块

shell> 47       # 设置 hugepage, 填一个值（512或其它）

shell> 49       # 绑定 IGB_UIO 模块
0000:02:02.0 '82545EM Gigabit Ethernet Controller (Copper) 100f' if=eth1 drv=e1000 unused=igb_uio,vfio-pci *Active*
0000:03:00.0 'VMXNET3 Ethernet Controller 07b0' if=eth0 drv=vmxnet3 unused=igb_uio,vfio-pci 
shell> 0000:03:00.0   # 绑定'VMXNET3'这个多队列网卡
```
### 1.9 解绑命令
```shell
shell> sudo ./usertools/dpdk-devbind.py --unbind 0000:03:00.0
shell> sudo ./usertools/dpdk-devbind.py --bind=vmxnet3 0000:03:00.0

shell> sudo ./usertools/dpdk-devbind.py --status

shell> sudo ip link set eth0 up
```