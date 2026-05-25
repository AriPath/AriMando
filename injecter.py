import sys
from abc import ABC, abstractmethod
from pydivert import WinDivert, Packet

class TcpInjector(ABC):
    def __init__(self, w_filter: str):
        self.w: WinDivert = WinDivert(w_filter)

    @abstractmethod
    def inject(self, packet: Packet):
        sys.exit("Not implemented")

    def run(self):
        with self.w:
            while True:
                packet = self.w.recv(65575)
                self.inject(packet)