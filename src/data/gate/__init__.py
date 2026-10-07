"""Gerbang bukti CLF (Langkah 3): satu modul aturan per kelompok label SR-BH 2020.

Urutan MODULES menentukan aturan penentu (`label_rule`) bila dua label menyumbang kelas yang sama.
"""

from . import code_injection, command, login_header, method, normal, protocol, rfi, scanner, sqli, traversal

MODULES = (sqli, code_injection, command, traversal, scanner, rfi, protocol, method, login_header, normal)
