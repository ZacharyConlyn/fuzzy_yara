#!/usr/bin/env python3

from pathlib import Path
from datetime import date
import hashlib

from binaryninja import show_message_box, log_info, log_warn, log_debug
from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, SidebarWidgetLocation, \
    SidebarContextSensitivity, UIContext, UIAction, Menu
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF, QSize
from PySide6.QtWidgets import QApplication, QFileDialog, QGridLayout, QHBoxLayout, QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QLabel, QWidget
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor

icon_as_b64 = """iVBORw0KGgoAAAANSUhEUgAAAHEAAABgCAYAAAAq9J3uAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAGHaVRYdFhNTDpjb20uYWRvYmUueG1wAAAAAAA8
P3hwYWNrZXQgYmVnaW49J++7vycgaWQ9J1c1TTBNcENlaGlIenJlU3pOVGN6a2M5ZCc/Pg0KPHg6
eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyI+PHJkZjpSREYgeG1sbnM6cmRmPSJodHRw
Oi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj48cmRmOkRlc2NyaXB0aW9u
IHJkZjphYm91dD0idXVpZDpmYWY1YmRkNS1iYTNkLTExZGEtYWQzMS1kMzNkNzUxODJmMWIiIHht
bG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIj48dGlmZjpPcmllbnRhdGlv
bj4xPC90aWZmOk9yaWVudGF0aW9uPjwvcmRmOkRlc2NyaXB0aW9uPjwvcmRmOlJERj48L3g6eG1w
bWV0YT4NCjw/eHBhY2tldCBlbmQ9J3cnPz4slJgLAAAKNklEQVR4Xu3df0wUZx4G8GeXxUXXCrJl
EQqHi+uPo54ogl6p9iShEWobsCY0xoQCqU0bz2jTRHsQPaWxCaamXGhTY5vC2XiJSdPQxgYbm8Bp
AkGUgkpLZWBBRvT2LLLIipiBvT8ED7+y7My8s7Cw7ycxmufdEJLHeXfmnV8Ax3HTT3c+IiJDp9P9
gQ74QnB4ePDSsrLNYZs2ZegNhmA6Lsd9QWhqfPHFz0k8sNHh+BfJAobugsVyRqfTbaEDWjLGxiKq
oACWnBwEm810WJH++npczcp6MnS7b2xwOOKeDAOHngZaCgoNRfxHH2FtXR2ee/dd5gIBwD08TKOA
57MSw9LSsKa6GlEFBdAZDHRYtWGXi0YBzyclRu3ciYSvv4YxOpoOMXt46xaNAp7mJcbs3Yv4Dz/U
dOsb76HDQaOAp2mJz2ZnI+6DD2jM+ZhmJRpjY2E7dozGmpsTFUWjgKdZiXFFRQgymWisOV9N0zOZ
JiXOtdkQkZ1NY58w8i3xKZqUGLljB418Rurvp1HA02TFJqmuDnOtVhorNuxywVlbi0FBgOR0YmRo
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"""

from capstone import *

def handle_inst(cap_inst):
    if cap_inst.op_count(CS_OP_MEM) == 1:
        return handle_mem_inst(cap_inst)
    if cap_inst.op_count(CS_OP_IMM) == 1:
        return handle_imm_inst(cap_inst)
    raise NotImplementedError(f"No ability to parse this instruction: {cap_inst}")
    
def handle_imm_inst(cap_inst):
    return create_byte_mask(cap_inst.bytes, cap_inst.encoding.imm_offset, cap_inst.encoding.imm_size)

def handle_mem_inst(cap_inst):
    return create_byte_mask(cap_inst.bytes, cap_inst.encoding.disp_offset, cap_inst.encoding.disp_size)

def create_byte_mask(inst_bytes, index, mem_size):
    if mem_size <= 0:
        raise ValueError("mem size cannot be zero")
    ret_list = [f"{b:02X}" if (i < index) or (i >= index + mem_size) else "??" for i, b in enumerate(inst_bytes)]

    found_bytes = sum(1 for x in ret_list if x == "??")
    if found_bytes != mem_size:
        raise Exception(f"create_byte_mask didn't get right answer: expected {mem_size} ??s but got {found_bytes}")
    return ret_list

class YaraRule():
    def __init__(self, name, base_addr):
        self.name = name
        self.base_addr = base_addr
        self.bytes_to_print = []
    
    def push_bytes(self, bytes_to_print):
        self.bytes_to_print.append(bytes_to_print)

    def get_rule(self):
        rule_str = f"${self.name} = " + "{"
        rule_string_spacer = len(rule_str)
        for i, b in enumerate(byte for instruction in self.bytes_to_print for byte in instruction):
            if i % 16 == 0 and i != 0:
                rule_str += "\n" + " " * rule_string_spacer
            rule_str += f" {b}" 
        rule_str += " }"


        min_bytes = Settings().get_integer("fuzzyyara.min_rule_bytes")
        if min_bytes > self.total_len():
            log_info(f"Rule '{rule_str}' must contain at least {min_bytes} bytes and it has {self.total_len()}", "FuzzyYara")
            return None

        min_non_wildcard = Settings().get_integer("fuzzyyara.min_non_wildcard_bytes")
        if min_non_wildcard > self.num_non_wildcards():
            log_info(f"Rule '{rule_str}' must contain at least at least {min_non_wildcard} non-wildcard bytes and it has {self.num_non_wildcards()}", "FuzzyYara")
            return None
        return rule_str

    
    def num_wildcards(self):
        return len([byte for instruction in self.bytes_to_print for byte in instruction if byte == "??"])
    
    def total_len(self):
        return len([byte for instruction in self.bytes_to_print for byte in instruction])
    
    def num_non_wildcards(self):
        return self.total_len() - self.num_wildcards()


class Function():

    def __init__(self, name, bv):
        self.name = name
        self.yara_rules = []
        self.bv = bv
        self.hash = None

    def create_valid_yara_name(self):
        ret_str = ""
        if not self.name[0].isalpha():
            ret_str = "_"
        return ret_str + "".join([char if char.isalnum() else "_" for char in self.name])

    def get_hash_of_file(self):
        if self.hash is None:
            raw_bv = self.bv.get_view_of_type("Raw")
            file_bytes = raw_bv.read(0, raw_bv.length)
            self.hash = hashlib.sha256(file_bytes).hexdigest()
        return self.hash

    def get_result(self):
        if self.yara_rules:
            self.yara_rules.sort(key=lambda x: x.base_addr)
        valid_rules = [rule.get_rule() for rule in self.yara_rules if rule.get_rule()]
        if not valid_rules:
            log_warn("No valid rules generated! Try changing the settings to allow for shorter rules or more wildcards", "FuzzyYara")
            return
        spacer = " " * 4
        result_str = "// auto-generated by FuzzyYara\n"
        result_str += f"rule {self.create_valid_yara_name()} " + "\n{\n"
        result_str += spacer + "meta:\n"
        result_str += spacer * 2 + "description = \"\"\n"
        result_str += spacer * 2 + "reference = \"\"\n" 
        result_str += spacer * 2 + "author = \"anonymous\"\n"
        result_str += spacer * 2 + "version = \"1.0\"\n"
        result_str += spacer * 2 + f"hash = \"{self.get_hash_of_file()}\" // SHA256\n"
        today = date.today().strftime("%Y-%m-%d")
        result_str += spacer * 2 + f"date = \"{today}\"\n"
        result_str += spacer + "strings:\n"
        for rule in valid_rules:
            for line in rule.split("\n"):
                result_str += spacer * 2 + line + "\n"
        result_str += spacer + "condition:\n"
        result_str += spacer * 2 + "all of them\n"
        result_str += "}"
        return result_str
        
    def add_yara_rule(self, rule):
        self.yara_rules.append(rule)
    
    def print_result(self):
        print(self.get_result())
        


def get_instructions_as_blocks(func):
    blocks = []
    for block in func:
        block_instructions = []
        address = block.start
        for instruction in block:
            block_instructions.append((instruction[0], instruction[1], address,))
            address += instruction[1]
        blocks.append(sorted(block_instructions, key=lambda x: x[2]))

    # instruction[0] -- actual instruction
    # instruction[1] -- size
    # instruction[2] -- address

    return blocks


def analyze_block(bv, instructions, md):
    expected_addr = instructions[0][2]
    for instruction in instructions:
        curr_addr = instruction[2]
        if curr_addr != expected_addr:
            raise ValueError(f"Expected address {expected_addr} but got {curr_addr}; Should not have gaps in basic blocks")
        expected_addr = curr_addr + instruction[1]
        inst = instruction[0]
        inst_bytes = bv.read(curr_addr, instruction[1])
        has_address = any(True for i in inst if "CodeRelativeAddressToken" in i.type.name)
        try:
            if has_address:
                cap_inst = next(md.disasm(inst_bytes, curr_addr))
                byte_pattern = handle_inst(cap_inst)
            else:
                if "address" in [i.type.name.lower() for i in inst]:
                    log_warn(f"Found possible missed instruction: {''.join(str(i) for i in inst)}", "FuzzyYara")
                byte_pattern = [f"{i:02X}" for i in inst_bytes]
            if len(byte_pattern) != len(inst_bytes):
                raise ValueError("The byte pattern length should match the instruction length")
            yield byte_pattern

        except Exception as e:
            context = UIContext.activeContext()
            if context:
                view = context.getCurrentView()
                if view:
                    view.navigate(curr_addr)
            raise e

def get_block_base_addr(block):
    return block[0][2]

def initialize_capstone(bv):
    if 'x86_64' == bv.arch.name:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif 'x86' == bv.arch.name:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        raise NotImplementedError("Cannot handle the binary's architecture!")
    md.detail = True
    return md

def get_widget():
    my_widget_list = [widget for widget in UIContext.activeContext().mainWindow().findChildren(FuzzyYaraSidebarWidget)]
    if not my_widget_list:
        show_message_box("Uh oh", "Open the widget because I'm a bad programmer")
    elif len(my_widget_list) > 1:
        show_message_box("Uh oh", "Found more than one widget i'm FREAKING OUT")
    else:
        return my_widget_list[0]
    

def run_fuzzy_yara_plugin_function(bv, func):
    widget = get_widget()
    if not widget:
        return
    md = initialize_capstone(bv)
    sorted_instructions = get_instructions_as_blocks(func)
    f = Function(func.name, bv)
    for block in sorted_instructions:
        block_name = "block_" + hex(get_block_base_addr(block))
        yara_rule = YaraRule(block_name, get_block_base_addr(block))
        for byte_pattern in analyze_block(bv, block, md):
            yara_rule.push_bytes(byte_pattern)
        f.add_yara_rule(yara_rule)
    widget.update_rules(f.get_result())


def run_fuzzy_yara_plugin_range(bv, start, size):
    widget = get_widget()
    if not widget:
        return
    md = initialize_capstone(bv)
    end = start + size
    curr_addr = start
    block_list = []
    f = Function(f"range_{hex(start)}", bv)
    while (curr_addr < end):
        blocks = bv.get_basic_blocks_at(curr_addr)
        if len(blocks) > 1:
            raise NotImplementedError("Currently cannot handle overlapping basic blocks")
        if len(blocks) < 1:
            log_info(f"skipping non-instruction data at {hex(curr_addr)}", "FuzzyYara")
            curr_addr = bv.get_next_basic_block_start_after(curr_addr)
            continue
        block = blocks[0]
        block_instructions = []
        curr_addr = block.start
        for instruction in block:
            inst_size = instruction[1]
            if curr_addr >= end:
                break
            if curr_addr < start:
                if (curr_addr + inst_size) > start:
                    raise NotImplementedError("TODO: handle partial instructions")
                log_debug(f"skipping instruction {''.join(i.text for i in instruction[0])} at address {hex(curr_addr)}", "FuzzyYara")
                curr_addr += inst_size
                continue
            if (curr_addr + inst_size) > end:
                raise NotImplementedError("TODO: handle partial instructions")
            block_instructions.append((instruction[0], instruction[1], curr_addr,))
            curr_addr += instruction[1]
        if block_instructions:
            block_list.append(sorted(block_instructions, key=lambda x: x[2]))
    for block in block_list:
        yara_rule = YaraRule(str(hex(get_block_base_addr(block))), get_block_base_addr(block))
        for byte_pattern in analyze_block(bv, block, md):
            yara_rule.push_bytes(byte_pattern)
        f.add_yara_rule(yara_rule)
    widget.update_rules(f.get_result())


    
class FuzzyYaraSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        global instance_id
        SidebarWidget.__init__(self, name)
        self.frame = frame
        self.data = data
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self.layout = QVBoxLayout()
        self.text_box = QTextEdit(self)
        self.text_box.setFontFamily("Courier New")
        self.layout.addWidget(self.text_box)
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.open_save_dialog)
        self.layout.addWidget(self.save_button)
        self.layout.setAlignment(QtCore.Qt.AlignCenter)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.setLayout(self.layout)
    
    def open_save_dialog(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "All Files (*.*);;Text Files (*.txt);;Binary Files (*.bin)")
        if file_path:
            with open(file_path, "wb") as outfile:
                outfile.write(self.text_box.toPlainText().encode("utf-8"))

    def notifyOffsetChanged(self, offset):
        pass

    def notifyViewChanged(self, view_frame):
        pass

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)
    
    def update_rules(self, text):
        self.text_box.setText(text)


class FuzzyYaraSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        import os
        current_dir = os.getcwd()
        print("Current working directory:", current_dir)
        log_info(f"Current working directory: {current_dir}", "FuzzyYara")
        import base64
        image_data = base64.b64decode(icon_as_b64)
        icon = QImage()
        icon.loadFromData(image_data)
        if icon.size() != QSize(56, 56):
            icon = icon.scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation)

        SidebarWidgetType.__init__(self, icon, "Fuzzy Yara Rule Editor")

    def createWidget(self, frame, data):
        return FuzzyYaraSidebarWidget("Fuzzy Yara Rule Editor", frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        return SidebarContextSensitivity.SelfManagedSidebarContext


Sidebar.addSidebarWidgetType(FuzzyYaraSidebarWidgetType())

Settings().register_group("fuzzyyara", "Fuzzy Yara Rule Generator")
Settings().register_setting(
    "fuzzyyara.min_rule_bytes",
    """
    {
        "title" : "set minimum total bytes for a rule",
        "type" : "number",
        "default" : 5,
        "description" : "Set the minimum number of bytes that will generate a rule.",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }"""
)

Settings().register_setting(
    "fuzzyyara.min_non_wildcard_bytes",
    """
    {
        "title" : "set minimum non-wildcard bytes",
        "type" : "number",
        "default" : 4,
        "description" : "Set the minimum number of non-wildcard bytes that will generate a rule.",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }"""
)


PluginCommand.register_for_function("Generate Fuzzy Yara rule (function)", "Generate a fuzzy Yara rule matching this function's basic blocks", run_fuzzy_yara_plugin_function)
PluginCommand.register_for_range("Generate Fuzzy Yara rule (range)", "Generate a fuzzy Yara rule matching the basic blocks in this range", run_fuzzy_yara_plugin_range)
