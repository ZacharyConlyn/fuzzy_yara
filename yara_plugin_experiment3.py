#!/usr/bin/env python3

from binaryninjaui import SidebarWidget, SidebarWidgetType, Sidebar, UIActionHandler, SidebarWidgetLocation, \
    SidebarContextSensitivity, UIContext, UIAction, Menu
from binaryninja.plugin import PluginCommand
from binaryninja.settings import Settings
from PySide6 import QtCore
from PySide6.QtCore import Qt, QRectF
from PySide6.QtWidgets import QApplication, QFileDialog, QGridLayout, QHBoxLayout, QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QLabel, QWidget
from PySide6.QtGui import QImage, QPixmap, QPainter, QFont, QColor


from capstone import *

def create_valid_yara_name(some_string):
    some_string = "test"
    some_string.replace
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
    if mem_size == 0:
        raise ValueError("mem size cannot be zero")
    ret_list = [f"{b:02X}" if (i < index) or (i >= index + mem_size) else "??" for i, b in enumerate(inst_bytes)]

    found_bytes = sum(1 for x in ret_list if x == "??")
    if found_bytes != mem_size:
        raise Exception(f"create_byte_mask didn't get right answer: expected {mem_size} ??s but got {found_bytes}")
    return ret_list

class YaraRule():
    def __init__(self, name):
        self.name = name
        self.bytes_to_print = []
    
    def push_bytes(self, bytes_to_print):
        self.bytes_to_print.append(bytes_to_print)

    def get_rule(self):
        rule_str = f"${self.name} = " + "{" + \
                " ".join(byte for instruction in self.bytes_to_print for byte in instruction) + \
                "}"

        min_bytes = Settings().get_integer("fuzzyyara.min_rule_bytes")
        if min_bytes > self.total_len():
            print(f"Rule ({rule_str}) must contain at least {min_bytes} bytes and it has {self.total_len()}")
            return None

        min_non_wildcard = Settings().get_integer("fuzzyyara.min_non_wildcard_bytes")
        if min_non_wildcard > self.num_non_wildcards():
            print(f"Rule ({rule_str}) must contain at least at least {min_non_wildcard} non-wildcard bytes and it has {self.num_non_wildcards()}")
            return None

        return rule_str

    
    def num_wildcards(self):
        return len([byte for instruction in self.bytes_to_print for byte in instruction if byte == "??"])
    
    def total_len(self):
        return len([byte for instruction in self.bytes_to_print for byte in instruction])
    
    def num_non_wildcards(self):
        return self.total_len() - self.num_wildcards()


class Function():
    def __init__(self, name, addr):
        self.name = name
        self.addr = addr
        self.yara_rules = []
    def get_result(self):
        return f"rule {self.name}" +  " {\n\tstrings:\n" + "".join((f"\t\t{rule.get_rule()}\n") for rule in self.yara_rules if rule.get_rule()) + "\n\tcondition:\n\t\tall of them\n}"
        
    def add_yara_rule(self, rule):
        self.yara_rules.append(rule)
    
    def print_result(self):
        print(self.get_result())
        


def get_instructions_as_blocks(func):
    # read all the instructions in the function
    # and record their address and size
    # we use blocks here instead of directly because blocks gives us the size of the instruction
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
                    print(f"[INFO] Found possible missed instruction: {"".join(str(i) for i in inst)}")
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

def initialize_capstone():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md

def run_yara_plugin_function(bv, func):
    md = initialize_capstone()

    # analyze the function under the cursor

    sorted_instructions = get_instructions_as_blocks(func)
    f = Function(func.name, func.start)
    for block in sorted_instructions:
        block_name = "block_" + hex(get_block_base_addr(block))
        yara_rule = YaraRule(block_name)
        for byte_pattern in analyze_block(bv, block, md):
            yara_rule.push_bytes(byte_pattern)
        f.add_yara_rule(yara_rule)
    return f.get_result()


def run_yara_plugin_range(bv, start, size):
    print(f"run_yara_plugin_range called with start: {start}, sie:{size}")
    md = initialize_capstone()
    end = start + size
    curr_addr = start
    block_list = []
    f = Function("range", start)
    while (curr_addr < end):
        blocks = bv.get_basic_blocks_at(curr_addr)
        if len(blocks) > 1:
            raise NotImplementedError("Currently cannot handle overlapping basic blocks")
        if len(blocks) < 1:
            print(f"[INFO] skipping non-instruction data at {hex(curr_addr)}")
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
                print(f"skipping instruction {instruction}")
                curr_addr += inst_size
                continue
            if (curr_addr + inst_size) > end:
                print("Handling partial instruction")
                raise NotImplementedError("TODO: handle partial instructions")
            block_instructions.append((instruction[0], instruction[1], curr_addr,))
            curr_addr += instruction[1]
        if block_instructions:
            block_list.append(sorted(block_instructions, key=lambda x: x[2]))
    for block in block_list:
        yara_rule = YaraRule(str(hex(get_block_base_addr(block))))
        for byte_pattern in analyze_block(bv, block, md):
            yara_rule.push_bytes(byte_pattern)
        f.add_yara_rule(yara_rule)
    print(f.get_result())
    #return f.get_result()


    
# Sidebar widgets must derive from SidebarWidget, not QWidget. SidebarWidget is a QWidget but
# provides callbacks for sidebar events, and must be created with a title.
class FuzzyYaraSidebarWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        global instance_id
        SidebarWidget.__init__(self, name)
        self.frame = frame
        self.data = data
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        UIAction.registerAction(f"FuzzyYara\\Generate Signature On Function")
        self.actionHandler.globalActions().bindAction("FuzzyYara\\Generate Signature On Function", UIAction(self.gen_sig_on_func))
        Menu.mainMenu("Plugins").addAction(f"FuzzyYara\\Generate Signature On Function", "FuzzyYara", 0)
        self.layout = QVBoxLayout()
        self.text_box = QTextEdit(self)
        self.layout.addWidget(self.text_box)
        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.open_save_dialog)
        self.layout.addWidget(self.save_button)
        self.layout.setAlignment(QtCore.Qt.AlignCenter)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(0)
        self.setLayout(self.layout)
    
    def open_save_dialog(self):
        file_path, dunno = QFileDialog.getSaveFileName(self, "Save File", "", "All Files (*.*);;Text Files (*.txt);;Binary Files (*.bin)")
        if file_path:
            with open(file_path, "wb") as outfile:
                print(f"Writing this: {self.text_box.toPlainText()}")
                outfile.write(self.text_box.toPlainText().encode("utf-8"))

    
    def gen_sig_on_func(self, view):
        if not view:
            print("NO VIEW")
            return
        function = view.function
        
        output = run_yara_plugin_function(view.binaryView, function)
        self.text_box.setText(output)
        #self.activateWindow()
        #self.focusWidget()
        self.setVisible(True)
        self.setHidden(False)
        #print(dir(self))
    

    def notifyOffsetChanged(self, offset):
        pass

    def notifyViewChanged(self, view_frame):
        pass
        if view_frame is None:
            self.data = None
        else:
            #self.datatype.setText(view_frame.getCurrentView())
            view = view_frame.getCurrentViewInterface()
            #self.text_box.setText("Cool :)")

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)
    
    def update_rules(self, text):
        self.text_box.setText(text)


class FuzzyYaraSidebarWidgetType(SidebarWidgetType):
    def __init__(self):
        # Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
        # HiDPI display compatibility. They will be automatically made theme
        # aware, so you need only provide a grayscale image, where white is
        # the color of the shape.
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)

        # Render an "H" as the example icon
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 56))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "Y")
        p.end()

        SidebarWidgetType.__init__(self, icon, "Fuzzy Yara Rule Editor")

    def createWidget(self, frame, data):
        # This callback is called when a widget needs to be created for a given context. Different
        # widgets are created for each unique BinaryView. They are created on demand when the sidebar
        # widget is visible and the BinaryView becomes active.
        return FuzzyYaraSidebarWidget("Fuzzy Yara Rule Editor", frame, data)

    def defaultLocation(self):
        # Default location in the sidebar where this widget will appear
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):
        # Context sensitivity controls which contexts have separate instances of the sidebar widget.
        # Using `contextSensitivity` instead of the deprecated `viewSensitive` callback allows sidebar
        # widget implementations to reduce resource usage.

        # This example widget uses a single instance and detects view changes.
        return SidebarContextSensitivity.SelfManagedSidebarContext


# Register the sidebar widget type with Binary Ninja. This will make it appear as an icon in the
# sidebar and the `createWidget` method will be called when a widget is required.
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

#PluginCommand.register_for_function("Write Yara rule (function)", "Write a Yara rule matching this function's basic blocks", self.my_custom_action)
PluginCommand.register_for_range("Write Yara rule (range)", "Write Yara rule matching the basic blocks in this range", run_yara_plugin_range)