from tkinter import messagebox as tkMessageBox
import requests
import urllib
from bs4 import BeautifulSoup
import time
import helper

class eGela:
    _login = 0
    _cookiea = ""
    _ikasgaia = ""
    _refs = []
    _root = None

    def __init__(self, root):
        self._root = root

    def check_credentials(self, username, password, event=None):
        popup, progress_var, progress_bar = helper.progress("check_credentials", "Logging into eGela...")
        progress = 0
        progress_var.set(progress)
        progress_bar.update()

        print("##### 1. ESKAERA (Login inprimakia lortu 'logintoken' ateratzeko #####")
        # sartu kodea hemen

        print("##### HTML-aren azterketa... #####")
        # sartu kodea hemen

        progress = 25
        progress_var.set(progress)
        progress_bar.update()
        time.sleep(0.1)

        print("\n##### 2. ESKAERA (Kautotzea -datu bidalketa-) #####")
        # sartu kodea hemen

        progress = 50
        progress_var.set(progress)
        progress_bar.update()
        time.sleep(0.1)

        print("\n##### 3. ESKAERA (berbidalketa) #####")
        # sartu kodea hemen

        progress = 75
        progress_var.set(progress)
        progress_bar.update()
        time.sleep(0.1)

        print("\n##### 4. ESKAERA (eGelako orrialde nagusia) #####")
        # sartu kodea hemen

        progress = 100
        progress_var.set(progress)
        progress_bar.update()
        time.sleep(0.1)
        popup.destroy()

        print("\n##### LOGIN EGIAZTAPENA #####")
        if LOGIN_EGIAZTAPENA:
            # sartu kodea hemen

            # KLASEAREN ATRIBUTUAK EGUNERATU
            self._root.destroy()
            # sartu kodea hemen

        else:
            tkMessageBox.showinfo("Alert Message", "Login incorrect!")

    def get_pdf_refs(self):
        popup, progress_var, progress_bar = helper.progress("get_pdf_refs", "Downloading PDF list...")
        progress = 0
        progress_var.set(progress)
        progress_bar.update()

        print("\n##### 5. ESKAERA (Ikasgairen eGelako orrialdea) #####")
        # sartu kodea hemen

        progress_step = float(100.0 / len(self._refs))

        print("\n##### HTML-aren azterketa... #####")
        # sartu kodea hemen

            progress += progress_step
            progress_var.set(progress)
            progress_bar.update()
            time.sleep(0.1)

        print(self._refs)
        popup.destroy()

        return self._refs

    def get_pdf(self, selection):
        print("##### PDF-a deskargatzen... #####")
        # sartu kodea hemen

        return pdf_name, pdf_file
