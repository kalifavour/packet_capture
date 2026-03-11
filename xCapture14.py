import tkinter as tk
from tkinter import ttk, font, messagebox
import os, sys
from datetime import datetime
from scapy.all import *
from scapy.layers.snmp import SNMP

# =====================================================
# Packet Formatter
# =====================================================
class PacketFormatter: # PacketFormatter
    def __init__(self):
        self.base_tab = '   '
        self.xtab = ''

    def show_packet(self, p):
        self.xtab = ''
        result = ''

        layers = [layer.__name__ for layer in p.layers()]
        #result += f'{layers=}\n'

        for idx, layer in enumerate(layers, start=1):
            result += f'###[ {layer} ]###\n'
            if layer == 'SNMP':
                break

            self.xtab = self.base_tab * idx
            for field in p[layer].fields_desc:
                key = field.name
                value = getattr(p[layer], key, None)
                if value is None:
                    continue
                result += (
                    f'{self.xtab}{key:<10}'
                    f'({value.__class__.__name__:<10}) = {value}\n'
                )
                # value.__class__.__name__ -> type 출력.

        if p.haslayer(SNMP):
            result += self._show_snmp(p)

        return result

    def _show_snmp(self, p):
        snmp = p[SNMP]
        result = ''
        self.xtab += self.base_tab

        # ──────────────────────────────
        # SNMP header
        # ──────────────────────────────
        for field in snmp.fields_desc:
            key = field.name
            if key == 'PDU':
                result += f'{self.xtab}\\PDU   \\\n'
                break

            value = getattr(snmp, key, None)
            result += (
                f'{self.xtab}{key:<10}'
                f'({value.__class__.__name__:<15}) = {repr(value)}\n'
            )

        # pdu_classes(8개) = [ SNMPget,SNMPnext,SNMPresponse,SNMPset,SNMPbulk,
        #                    SNMPinform,SNMPtrapv1,SNMPtrapv2 ]
        # ──────────────────────────────
        # PDU - class
        # ──────────────────────────────
        pdu = snmp.PDU
        self.xtab += ' '

        pdu_layer = pdu.layers()        # pdu class 추출.
        #print(f'{len(pdu_layer)=}')    # pdu class는 반드시 1개만 존재함.    
        if pdu_layer:
            result += f'{self.xtab}###[ {pdu_layer[0].__name__} ]###\n'
            
            self.xtab += self.base_tab

            for field in pdu.fields_desc:
                key = field.name
                if key == 'varbindlist':
                    result += f'{self.xtab}\\varbindlist\\\n'
                    break

                value = getattr(pdu, key, None)
                if value is None:
                    continue
                result += (
                    f'{self.xtab}{key:<12}'
                    f'({value.__class__.__name__:<14}) = {repr(value)}\n'
                )

        # ──────────────────────────────
        # varbindlist - desc
        # ──────────────────────────────
        self.xtab += ' '

        for vb in pdu.varbindlist: # vb: pdu의 sub_class (여러개 있을수 있음)
            result += f'{self.xtab}###[ {vb} ]###\n'
            for f in vb.fields_desc:
                key = f.name
                value = getattr(vb, key, None)
                result += (
                    f'{self.xtab}{self.base_tab}{key:<14}'
                    f'({value.__class__.__name__:<15}) = {repr(value)}\n'
                )

        return result

# =====================================================
# Main Sniffer Application (GUI + Logic)
# =====================================================
class SnifferGUI:
    FILE_CELL = 'packetCell.txt'
    FILE_PCAP = 'packet.pcap'
    FILE_TEXT = 'packet.txt'
    FILE_FILTER = 'filterlist.txt'

    def __init__(self):
        self.packet_text_all = ''
        self.filter_list = self._load_filter_history()
        self.formatter = PacketFormatter()

        self._build_gui()

    # ---------------- GUI ----------------
    def _build_gui(self):
        self.win = tk.Tk()
        self.win.title(f"Packet Capture - {os.path.basename(__file__)}{' '*45}by JYHn")
        self.win.geometry('540x110+1350+16')
        self.win.resizable(False, False)

        px = 5
        f1 = tk.Frame(self.win)
        f2 = tk.Frame(self.win)
        f3 = tk.Frame(self.win)

        f1.pack(fill='both', padx=px, pady=5)
        f2.pack(fill='both', padx=px)
        f3.pack(fill='both', padx=px, pady=5)

        myFont13 = font.Font(family='Helvetica', size=13)
        myFont11 = font.Font(family='Helvetica', size=11)

        # Filter
        self.label_filter = tk.Label(f1, text='Enter BPF filter', width=13, anchor='w', font=myFont13)
        self.label_filter.pack(side='left', padx=10)

        self.combo_filter = ttk.Combobox(
            f1, values=self.filter_list, width=40, font=myFont13
        )
        self.combo_filter.pack(side='left')
        self.combo_filter.focus_set()
        self.combo_filter.bind('<Return>', lambda e: self.combo_count.focus_set())

        # Count
        tk.Label(f2, text='Packet Counter', width=13, anchor='w', font=myFont13).pack(side='left', padx=10)
        self.combo_count = ttk.Combobox(
            f2, width=5, font=myFont13,
            values=[str(i) for i in range(1, 11)],
            state='readonly'
        )
        self.combo_count.current(1)
        self.combo_count.pack(side='left')
        self.combo_count.bind('<Return>', lambda e: self.capture())

        tk.Label(
            f2,
            text=f'(Save) {self.FILE_CELL}, {self.FILE_PCAP}, {self.FILE_TEXT}',
            font=myFont11,
        ).pack(side='left', padx=10)

        tk.Button(f3, text=f'Capture ', 
            width=25, relief='raised', activebackground='beige', 
            overrelief='groove', command=self.capture, font=myFont13).pack(side='left', padx=10)

        tk.Label(f3, text='Timeout', font=myFont11).pack(side='left', padx=5)
        self.combo_timeout = ttk.Combobox(
            f3, width=3, font=myFont13,
            values=[str(i) for i in range(0, 31, 5)],
            state='readonly'
        )
        self.combo_timeout.current(2)
        self.combo_timeout.pack(side='left')


        tk.Button(f3, text='종료', width=13, relief='raised', activebackground='beige', 
            overrelief='groove', command=self.exit, font=myFont13).pack(side='right', padx=10)

        self.win.protocol("WM_DELETE_WINDOW", self.exit)
        self.win.mainloop()

    # ---------------- Logic ----------------
    def capture(self):
        self.packet_text_all = ''

        flt = self.combo_filter.get().strip()
        if not flt: return

        count = int(self.combo_count.get())
        timeout = int(self.combo_timeout.get())

        #  패킷 캡처
        try:
            packets = sniff(filter=flt, count=count, timeout=timeout)
            self.label_filter.config(text='Enter BPF filter', fg='black')
        except Exception:
            self.label_filter.config(text='Wrong Filter', fg='red')
            return

        if not packets: 
            self.label_filter.config(text='Time out !', fg='red')
            return

        #  파일 초기화
        self._init_files(flt)

        header = (
            f'* {self.FILE_TEXT:<15} : p.show(dump=True)\n'
            f'* {self.FILE_CELL:<15} : layer/field 분석\n'
            f'* {self.FILE_PCAP:<15} : wrpcap()\n\n'
            f'* Filter  : {flt}\n'
            f'* Date    : {datetime.now()}\n\n'
        )

        packet_summary = f"\n[+] {len(packets)} packets saved.\n"

        #  헤더 기록
        self.packet_text_all += header
        with open(self.FILE_CELL, 'w', encoding='utf-8') as f:
            f.write(header)

        #  패킷 처리
        with open(self.FILE_CELL, 'a', encoding='utf-8') as f:
            for idx, pkt in enumerate(packets, start=1):
                head = f'\n*** ({idx}) Head) {pkt}\n'

                self.packet_text_all += head
                self.packet_text_all += pkt.show(dump=True)

                f.write(head)
                f.write(self.formatter.show_packet(pkt))

                wrpcap(self.FILE_PCAP, pkt, append=True)

        #  요약 정보 포함 파일로 저장.
        with open(self.FILE_CELL, 'a', encoding='utf-8') as f:
            f.write(packet_summary)

        self.packet_text_all += packet_summary
        with open(self.FILE_TEXT, 'w', encoding='utf-8') as f:
            f.write(self.packet_text_all)


    def _init_files(self, flt):
        for f in (self.FILE_CELL, self.FILE_PCAP, self.FILE_TEXT):
            if os.path.exists(f):
                os.remove(f)

        if flt in self.filter_list:
            self.filter_list.remove(flt)
        self.filter_list.insert(0, flt)
        self.combo_filter.configure(values=self.filter_list)

    def _load_filter_history(self):
        if not os.path.exists(self.FILE_FILTER):
            return []
        with open(self.FILE_FILTER, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f]

    def exit(self):
        with open(self.FILE_FILTER, 'w', encoding='utf-8') as f:
            for item in self.filter_list:
                f.write(item + '\n')
        self.win.destroy()
        sys.exit(0)

# =====================================================
# Run
# =====================================================
if __name__ == '__main__':
    SnifferGUI()
