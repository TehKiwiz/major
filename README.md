Occluding IEEE 802.11
=====

This program listens for beacons sent from wireless access points in the range of your
wireless station. Once received the program extracts the BSSID of the AP and transmits
deauthentication packets using the broadcast MAC address. This results to the disconnection of all
clients connected to the AP at the time of the attack. This is essencially a WiFi DoS attack tool
created to Authorising selective users access to the wireless network and hence saving connection
bandwith. It works only in Linux and requires wireless card drivers capable of injecting packets in
wireless networks.

Download the program from aour git repositry:

https://github.com/ankurloonia/major

Its a simple C program which can be compiled with the command

gcc -lpthreads wifi.c -o wifi.out

How to use it: Just run it as root and put as first argument the card interface. It will automatically
put your interface in monitor mode and it will listen at channel range 1-14. If there is no AP in the
channel, it will change channel every 1 second, or else it will start the attack which it takes
approximately 30 seconds. After that it will change channel.

The output file can be run only with administrative priviledges, i.e. prefixed with sudo or su and the
input takes a compulsory argument, i.e. name of the wireless card and two optional arguments

Options:
-c channels Channel list (e.g 1,4-6,11) (default: 1-14)
-l Display all network interfaces and exit

For example:

sudo ./wifi.out -c 1 wlan0

This will inject deauthentication frames on channel 1 using the 'wlan0' wireless interface.
