import colored

##Colors##
def RED(string):
    return colored.stylize(string, colored.fg("red"))

def GREEN(string):
    return colored.stylize(string, colored.fg("light_green"))

def YELLOW(string):
    return colored.stylize(string, colored.fg("yellow"))

def BLUE(string):
    return colored.stylize(string, colored.fg("blue"))

def MAGENTA(string):
    return colored.stylize(string, colored.fg("magenta"))

def PINK(string):
    return colored.stylize(string, colored.fg("deep_pink_4c"))

def ORANGE(string):
    return colored.stylize(string, colored.fg("208"))    

##Formats##
def WARN(string):
    return RED("[!] ") + string

def FULLWARN(string):
    return RED("[!] " + string)

def FULLGREENWARN(string):
    return GREEN("[!] " + string)

def FULLINFO(string):
    return YELLOW("[i] " + string)

def INFO(string):
    return YELLOW("[i] ") + string

def SUCCESS(string):
    return GREEN("[+] ") + string

def FULLSUCCESS(string):
    return GREEN("[+] " + string)

def FAIL(string):
    return RED("[-] ") + string

def DOING(string):
    return BLUE("[*] ") + string

def INPUT(string):
    return MAGENTA("[?] ") + string

def END(string):
    return PINK("[i] " + string)
