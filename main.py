from hackEngine import ProcMemoryMain, ResolveType
from kivy.app import App
from kivy.uix.widget import Widget
from kivy.config import Config
from kivy.resources import resource_add_path
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock

import sys
import os

# pyinstaller --name hollowKnight --onefile --noconsole main.py
# pyinstaller main.spec

IconPath = 'Icon.ico'


class RootUI(GridLayout):

    def __init__(self, **kwargs):
        super(RootUI, self).__init__(**kwargs)


class HackGridUI(GridLayout):

    def __init__(self, **kwargs):
        super(HackGridUI, self).__init__(**kwargs)


class OnlineCellUI(Widget):

    def __init__(self, **kwargs):
        super(OnlineCellUI, self).__init__(**kwargs)


class HackCellUI(GridLayout):

    def __init__(self, **kwargs):
        super(HackCellUI, self).__init__(**kwargs)


class HackCell:
    cell = None
    lbl = None
    btn = None
    txtBox = None

    procMem = None

    btnEnable = False

    def __init__(self, index, hackUnit, procMem):
        self.cell = HackCellUI()
        self.lbl = self.cell.ids['hackLbl']
        self.lbl.text = hackUnit.desc
        self.btn = self.cell.ids['hackBtn']
        self.btn.fbind('on_press', self.btnClick, index)
        self.txtBox = self.cell.ids['hackTxtBox']
        self.hackUnit = hackUnit
        self.procMem = procMem

        self.hackUnit.bindUI(self)
        self.txtBoxInit()

    def txtBoxInit(self):
        if self.hackUnit.hackType == ResolveType.injectCode:
            self.txtBox.text = self.hackUnit.injectSet.newVal
        else:
            self.hideWid(self.txtBox)

    def btnDisable(self, flag):
        self.btn.disabled = flag

    def btnToggle(self):
        self.btnEnable = not self.btnEnable

    def btnClick(self, index, obj):
        # function on
        if not self.btnEnable:
            if self.procMem.hackMem(index):
                self.btn.text = "on"
                self.btn.color = 0, 1, 0, 1
                self.btnToggle()

        else:
            if self.procMem.resetMem(index):
                self.btn.text = "off"
                self.btn.color = 1, 0, 0, 1
                self.btnToggle()

    def hideWid(self, wid):
        wid.size_hint_y, wid.opacity, wid.disabled = None, 0, True


class CheatApp(App):

    def __init__(self, **kwargs):
        super(CheatApp, self).__init__(**kwargs)
        self.title = 'Game Cheat'
        self.icon = IconPath

        Config.set('graphics', 'width', '500')
        Config.set('graphics', 'height', '500')

    def cheatMainInit(self, dt=None):
        self.procMem.openProcess()
        self.onlineState(self.procMem.isOpenProcess())

    def UIInit(self):
        hackUnits = self.procMem.hackUnits
        self.cheatBtnLen = len(hackUnits)
        self.hackCells = []

        root = RootUI()

        onlineCellUI = OnlineCellUI()
        onlineCellUI.ids['reloadBtn'].on_press = self.reloadEvent
        self.onlineCellUI = onlineCellUI

        grid = HackGridUI()
        root.add_widget(onlineCellUI)
        root.add_widget(grid)

        for i, hackUnit in enumerate(hackUnits):
            hackCell = HackCell(i, hackUnit, self.procMem)
            grid.add_widget(hackCell.cell)
            self.hackCells.append(hackCell)

        return root

    def onlineState(self, isOnline):
        lblStyles = {
            True: {'text': 'online', 'color': (0, 1, 0, 1)},
            False: {'text': 'offline', 'color': (1, 0, 0, 1)}

        }
        for x in range(self.cheatBtnLen):
            self.hackCells[x].btnDisable(not isOnline)

        style = lblStyles[isOnline]
        self.onlineCellUI.ids['onlineLbl'].text = style['text']
        self.onlineCellUI.ids['onlineLbl'].color = style['color']
        self.onlineCellUI.ids['reloadBtn'].disabled = isOnline

    def reloadEvent(self):
        self.cheatMainInit()

    def build(self):
        self.procMem = ProcMemoryMain()
        Clock.schedule_once(self.cheatMainInit, 0.5)
        return self.UIInit()

    def on_stop(self):
        self.procMem.closeHandle()


def resourcePath():
    # _MEIPASS is a temporary folder for PyInstaller
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS)

    return os.path.join(os.path.abspath("."))


if __name__ == '__main__':
    # add some local file for PyInstaller
    resource_add_path(resourcePath())
    CheatApp().run()
