#!/usr/bin/env python3
from consolemenu import *
from consolemenu.items import *
from consolemenu.format import *
from datetime import datetime
import asyncio
import subprocess
import os


class bcolors:
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    YELLOW = '\033[93m'
    PURPLE = '\033[95m'
    FAILRED = '\033[91m'
    ENDC = '\033[0m'

target = "" # 172.16.169.0/24 / hosts file
username =""
password =""
domain = ""
text = ""
nthash = ""

async def run_command(*args):
    # Create subprocess

    process = await asyncio.create_subprocess_exec(
        *args,
        # stdout must a pipe to be accessible as process.stdout
        stdout=asyncio.subprocess.PIPE)
    # Wait for the subprocess to finish
    stdout, stderr = await process.communicate()
    # Return stdout
    protocols=[b'SSH',b'MSSQL',b'SMB',b'RPC',b'FTP',b'WINRM',b'WMI',b'RDP',b'VNC',b'LDAP']
    command = ""
    for i in args:
        command = command+ i + " "
    print("\n======[ "+command+" ]======")
    for row in stdout.split(b'\n'):
        if(b'[+]' in row or b'[-]' in row or b'[*]' in row):
            for value in row.split():
                if (value in protocols):
                    newvalue = bcolors.OKBLUE + value.decode() + bcolors.ENDC
                    row = row.replace(value,newvalue.encode(),1)
                match value:
                    case b'[+]':
                        newvalue = bcolors.OKGREEN + value.decode() + bcolors.ENDC
                        row = row.replace(value,newvalue.encode(),1)
                    case b'[-]':
                        newvalue = bcolors.FAILRED + value.decode() + bcolors.ENDC
                        row = row.replace(value,newvalue.encode(),1)
                    case b'[*]':
                        newvalue = bcolors.PURPLE + value.decode() + bcolors.ENDC
                        row = row.replace(value,newvalue.encode(),1)
                    case b'(Pwn3d!)':
                        newvalue = bcolors.YELLOW + value.decode() + bcolors.ENDC
                        row = row.replace(value,newvalue.encode(),1)
            print(row.decode().strip())
    return stdout.decode().strip()

async def prepare_command(protocol:str, target:str, username:str, password:str) -> None:
    res = await run_command('netexec', protocol, target, '-u', username, '-p', password, '--continue-on-success')
    return res

async def prepare_command_domain(protocol:str, target:str, username:str, password:str, domain:str) -> None:
    res = await run_command('netexec', protocol, target, '-u', username, '-p', password, '-d', domain, '--continue-on-success')
    return res

async def prepare_command_localauth(protocol:str, target:str, username:str, password:str) -> None:
    res = await run_command('netexec', protocol, target, '-u', username, '-p', password, '--local-auth', '--continue-on-success')
    return res

async def prepare_command_pth(protocol:str, target:str, username:str, nthash:str) -> None:
    res = await run_command('netexec', protocol, target, '-u', username, '-H', nthash, '--continue-on-success')
    return res

async def prepare_command_pth_domain(protocol:str, target:str, username:str, nthash:str, domain:str) -> None:
    res = await run_command('netexec', protocol, target, '-u', username, '-H', nthash, '-d', domain, '--continue-on-success')
    return res

async def prepare_command_pth_localauth(protocol:str, target:str, username:str, nthash:str) -> None:
    res = await run_command('netexec', protocol, target, '-u', username, '-H', nthash, '--local-auth', '--continue-on-success')
    return res

def enum_smb_enum_hosts():
    print("Executing: netexec smb {0}".format(str(target)))
    subprocess.run(["netexec", "smb", str(target)])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()


def enum_smb_null_sessions_access():
    print("Executing: netexec smb {0} -u '' -p ''".format(str(target)))
    subprocess.run(["netexec", "smb", str(target) , "-u", "''" ,"-p", "''"])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()

def enum_smb_nullsessions_enum(param):
    print("Executing: netexec smb {0} -u '' -p '' {1}".format(str(target), param))
    subprocess.run(["netexec", "smb", str(target) , "-u", "''" ,"-p", "''", param])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()

def enum_smb_nullsessions_enum_all():
    print("Executing: netexec smb {0} -u '' -p '' --groups --local-groups --loggedon-users --rid-brute --sessions --users --shares --pass-pol".format(str(target)))
    subprocess.run(["netexec", "smb", str(target) , "-u", "''" ,"-p", "''", "--groups", "--local-groups","--loggedon-users","--rid-brute","--sessions","--users","--shares", "--pass-pol"])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()




def enum_smb_guest_sessions_access():
    print("Executing: netexec smb {0} -u 'guest' -p ''".format(str(target)))
    subprocess.run(["netexec", "smb", str(target) , "-u", "guest" ,"-p", "''"])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()

def enum_smb_guest_enum(param):
    print("Executing: netexec smb {0} -u 'guest' -p '' {1}".format(str(target), param))
    subprocess.run(["netexec", "smb", str(target) , "-u", "guest" ,"-p", "''", param])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()

def enum_smb_guest_enum_all():
    print("Executing: netexec smb {0} -u 'guest' -p '' --groups --local-groups --loggedon-users --rid-brute --sessions --users --shares --pass-pol".format(str(target)))
    subprocess.run(["netexec", "smb", str(target) , "-u", "guest" ,"-p", "''", "--groups", "--local-groups","--loggedon-users","--rid-brute","--sessions","--users","--shares", "--pass-pol"])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()



def enum_smb_authenticated_access(username, password):
    print("Executing: netexec smb {0} -u {1} -p {2}".format(str(target),str(username), str(password)))
    subprocess.run(["netexec", "smb", str(target) , "-u",  str(username) ,"-p", str(password)])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()

def enum_smb_authenticated_user_enum(username, password, param):
    print("Executing: netexec smb {0} -u {1} -p {2} {3}".format(str(target),str(username), str(password), param))
    subprocess.run(["netexec", "smb", str(target) , "-u",  str(username) ,"-p", str(password), param])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()

def enum_smb_authenticated_user_enum_all(username, password):
    print("Executing: netexec smb {0} -u {1} -p {2} --groups --local-groups --loggedon-users --rid-brute --sessions --users --shares --pass-pol".format(str(target),str(username), str(password)))
    subprocess.run(["netexec", "smb", str(target) , "-u",  str(username) ,"-p", str(password), "--groups", "--local-groups","--loggedon-users","--rid-brute","--sessions","--users","--shares", "--pass-pol"])
    pu = PromptUtils(Screen())
    pu.enter_to_continue()

def enum_all_check_for_authenticated_access():
    startTime = datetime.now()
    task_list = []
    if password:
        task_list.append(prepare_command('smb',target,username,password) )
        task_list.append(prepare_command_localauth('smb',target,username,password))

        task_list.append(prepare_command('mssql',target,username,password) )
        task_list.append(prepare_command_localauth('mssql',target,username,password))

        task_list.append(prepare_command('winrm',target,username,password) )

        task_list.append(prepare_command('rdp',target,username,password) )
        
        task_list.append(prepare_command('ssh',target,username,password) )

        task_list.append(prepare_command('ftp',target,username,password) )

        task_list.append(prepare_command('wmi',target,username,password) )
        
        task_list.append(prepare_command_localauth('wmi',target,username,password))

        task_list.append(prepare_command('vnc',target,username,password) )

        task_list.append(prepare_command('ldap',target,username,password) )

        if domain:
            task_list.append(prepare_command_domain('smb',target,username,password,domain))
            task_list.append(prepare_command_domain('mssql',target,username,password,domain))
            task_list.append(prepare_command_domain('winrm',target,username,password,domain))
            task_list.append(prepare_command_domain('rdp',target,username,password,domain))
            task_list.append(prepare_command('ssh',target,username+'@'+domain,password) )
            task_list.append(prepare_command_domain('wmi',target,username,password,domain))
            task_list.append(prepare_command_domain('ldap',target,username,password,domain))

    if nthash:
        task_list.append(prepare_command_pth('smb',target,username,nthash) )
        task_list.append(prepare_command_pth_localauth('smb',target,username,nthash))

        task_list.append(prepare_command_pth('mssql',target,username,nthash) )
        task_list.append(prepare_command_pth_localauth('mssql',target,username,nthash))

        task_list.append(prepare_command_pth('winrm',target,username,nthash) )

        task_list.append(prepare_command_pth('rdp',target,username,nthash) )

        task_list.append(prepare_command_pth('wmi',target,username,nthash) )
        task_list.append(prepare_command_pth_localauth('wmi',target,username,nthash))

        task_list.append(prepare_command_pth('ldap',target,username,nthash) )
       
        if domain:
            task_list.append(prepare_command_pth_domain('smb',target,username,nthash,domain))
            task_list.append(prepare_command_pth_domain('mssql',target,username,nthash,domain))
            task_list.append(prepare_command_pth_domain('winrm',target,username,nthash,domain))
            task_list.append(prepare_command_pth_domain('rdp',target,username,nthash,domain))
            task_list.append(prepare_command_pth_domain('wmi',target,username,nthash,domain))
            task_list.append(prepare_command_pth_domain('ldap',target,username,nthash,domain))

    else:
        print("No Password and no hash set")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    commands = asyncio.gather(*task_list)
    reslt = loop.run_until_complete(commands)
    loop.close()
    print("Done! Execution duration: "+str(datetime.now() - startTime))
    pu = PromptUtils(Screen())
    pu.enter_to_continue()



def restart():
    os.execl(sys.executable, sys.executable, *sys.argv)

def setValuesAndStart():
    global target
    target = input("Input Target address or Subnet: ")
    global username
    username = input("Input Username: ")
    global password
    password = input("Input Password: ")
    global nthash
    nthash = input("Input NT Hash: ")
    global domain
    domain = input("Input Target Domain: ")

    selectedTarget = "Target: " + str(target)+"\n"
    selectedUsername = "Username: " + str(username)+"\n"
    selectedPassword = "Password: " + str(password)+"\n"
    selectedNTHash = "NT Hash: " + str(nthash)+"\n"
    selectedDomain = "Domain: " + str(domain)+"\n"
    global text
    text = selectedTarget +selectedUsername +selectedPassword+ selectedNTHash +selectedDomain
    global menu
    menu = ConsoleMenu("NetExec Wrapper", "By S.1.l.k.y (Maximilian Barz)\nVersion 0.2",prologue_text=text, formatter=MenuFormatBuilder().set_title_align('center').set_subtitle_align('center').show_prologue_top_border(True).show_prologue_bottom_border(True))

    # Create Enumeration Submenu entry in Main Menu
    enumeration_submenu = SelectionMenu("","Enumeration Menu",prologue_text=text, formatter=MenuFormatBuilder().set_title_align('center').set_subtitle_align('center').show_prologue_top_border(True).show_prologue_bottom_border(True))
    submenu_enumeration = SubmenuItem("Enumeration", enumeration_submenu, menu)

    # Create Access Check Submenu entry in Main Menu
    Check_Access_Submenu = SelectionMenu("","Check for Authenticated Access",prologue_text=text, formatter=MenuFormatBuilder().set_title_align('center').set_subtitle_align('center').show_prologue_top_border(True).show_prologue_bottom_border(True))
    Check_Access_Submenu_item = SubmenuItem("Check for Authenticated Access", Check_Access_Submenu, menu)

    #SubFunction in in Main Menu
    restart_function_item = FunctionItem("Set new Target Values", restart)
    check_for_authenticated_access = FunctionItem("Check Access for all protocols", enum_all_check_for_authenticated_access)

    # Create SMB Submenu entry in Sub Menu
    SMB_submenu = SelectionMenu("","SMB Enumeration",prologue_text=text, formatter=MenuFormatBuilder().set_title_align('center').set_subtitle_align('center').show_prologue_top_border(True).show_prologue_bottom_border(True))
    SMB_submenu_item = SubmenuItem("SMB Enumeration", SMB_submenu, enumeration_submenu)

    # SubMenus in SMB Submenu
    smb_null_anon_guest_enumeration_submenu = SelectionMenu("","SMB - Null Session,  Anonymous / Guest Logon Enumeration Menu",prologue_text=text, formatter=MenuFormatBuilder().set_title_align('center').set_subtitle_align('center').show_prologue_top_border(True).show_prologue_bottom_border(True))
    smb_authenticated_enumeration_submenu = SelectionMenu("","Authenticated SMB Enumeration Menu",prologue_text=text, formatter=MenuFormatBuilder().set_title_align('center').set_subtitle_align('center').show_prologue_top_border(True).show_prologue_bottom_border(True))
    #text (str) – The text shown for this menu item; submenu (ConsoleMenu) – The submenu to be opened when this item is selected; menu (ConsoleMenu) – The menu to which this item belongs
    null_anon_guest_submenu_enumeration = SubmenuItem("SMB - Null Session,  Anonymous / Guest Logon Enumeration Menu", smb_null_anon_guest_enumeration_submenu, SMB_submenu)
    smb_authenticated_submenu_enumeration = SubmenuItem("SMB - Authenticated Enumeration Menu", smb_authenticated_enumeration_submenu, SMB_submenu)
    # SubFunction in SMB SubMenu
    smb_enum_hosts = FunctionItem("SMB - Enumerate live SMB hosts", enum_smb_enum_hosts)



    #Enumeration SMB Null Session Submenu Items
    smbNullSessionAccessfunction_item = FunctionItem("Perform SMB Null Session Access Enumeration", enum_smb_null_sessions_access)
    smbNullSessionEnumAllfunction_item = FunctionItem("Perform SMB Null Session - Enumerate Everything", enum_smb_nullsessions_enum_all)
    smbNullSessionUserEnumfunction_item = FunctionItem("Perform SMB Null Session User Enumeration", enum_smb_nullsessions_enum, ["--users"])
    smbNullSessionSharesEnumfunction_item = FunctionItem("Perform SMB Null Session Share Enumeration", enum_smb_nullsessions_enum, ["--shares"])
    smbNullSessionPassPolEnumfunction_item = FunctionItem("Perform SMB Null Session Password Policy Enumeration", enum_smb_nullsessions_enum, ["--pass-pol"])
    smbNullSessionGroupsEnumfunction_item = FunctionItem("Perform SMB Null Session Group Enumeration", enum_smb_nullsessions_enum, ["--groups"])
    smbNullSessionRidBruteEnumfunction_item = FunctionItem("Perform SMB Null Session RID Bruteforce", enum_smb_nullsessions_enum, ["--rid-brute"])
    smbNullSessionLoggedonUsersEnumfunction_item = FunctionItem("Perform SMB Null Session Group Enumeration", enum_smb_nullsessions_enum, ["--loggedon-users"])
    smbNullSessionLocalGroupsEnumfunction_item = FunctionItem("Perform SMB Null Session Local Group Enumeration", enum_smb_nullsessions_enum, ["--local-groups"])
    smbNullSessionSessionsEnumfunction_item = FunctionItem("Perform SMB Null Session Password Policy Enumeration", enum_smb_nullsessions_enum, ["--sessions"])

    #Enumeration SMB Guest Authentication Submenu Items
    smbGuestAccessfunction_item = FunctionItem("Perform SMB Guest Authentication Access Enumeration", enum_smb_guest_sessions_access)
    smbGuestEnumAllfunction_item = FunctionItem("Perform SMB Guest Authentication - Enumerate Everything", enum_smb_guest_enum_all)
    smbGuestUserEnumfunction_item = FunctionItem("Perform SMB Guest Authentication User Enumeration", enum_smb_guest_enum, ["--users"])
    smbGuestSharesEnumfunction_item = FunctionItem("Perform SMB Guest Authentication Share Enumeration", enum_smb_guest_enum, ["--shares"])
    smbGuestPassPolEnumfunction_item = FunctionItem("Perform SMB Guest Authentication Password Policy Enumeration", enum_smb_guest_enum, ["--pass-pol"])
    smbGuestGroupsEnumfunction_item = FunctionItem("Perform SMB Guest Authentication Group Enumeration", enum_smb_guest_enum, ["--groups"])
    smbGuestRidBruteEnumfunction_item = FunctionItem("Perform SMB Guest Authentication RID Bruteforce", enum_smb_guest_enum, ["--rid-brute"])
    smbGuestLoggedonUsersEnumfunction_item = FunctionItem("Perform SMB Guest Authentication Group Enumeration", enum_smb_guest_enum, ["--loggedon-users"])
    smbGuestLocalGroupsEnumfunction_item = FunctionItem("Perform SMB Guest Authentication Local Group Enumeration", enum_smb_guest_enum, ["--local-groups"])
    smbGuestSessionsEnumfunction_item = FunctionItem("Perform SMB Guest Authentication Password Policy Enumeration", enum_smb_guest_enum, ["--sessions"])


    #Enumeration SMB Authenticated Submenu Items
    smbAuthenticatedSessionAccessfunction_item = FunctionItem("Perform SMB Authenticated SMB Access Enumeration", enum_smb_authenticated_access, [username, password])
    smbAuthenticatedSessionEnumAllfunction_item = FunctionItem("Perform Authenticated SMB Enumeration - Enumerate Everything", enum_smb_authenticated_user_enum_all, [username, password])
    smbAuthenticatedSessionUserEnumfunction_item = FunctionItem("Perform Authenticated SMB User Enumeration", enum_smb_authenticated_user_enum, [username, password, "--users"])
    smbAuthenticatedSessionShareEnumfunction_item = FunctionItem("Perform Authenticated SMB Share Enumeration", enum_smb_authenticated_user_enum, [username, password, "--shares"])
    smbAuthenticatedSessionGroupEnumfunction_item = FunctionItem("Perform Authenticated SMB Group Enumeration", enum_smb_authenticated_user_enum, [username, password, "--groups"])
    smbAuthenticatedSessionLocalGroupEnumfunction_item = FunctionItem("Perform Authenticated SMB Local Group Enumeration", enum_smb_authenticated_user_enum, [username, password, "--local-groups"])
    smbAuthenticatedSessionLoggedonUsersEnumfunction_item = FunctionItem("Perform Authenticated SMB Loggedon Users Enumeration", enum_smb_authenticated_user_enum, [username, password, "--loggedon-users"])
    smbAuthenticatedSessionRidBruteEnumfunction_item = FunctionItem("Perform Authenticated SMB RID Bruteforce", enum_smb_authenticated_user_enum, [username, password, "--rid-brute"])
    smbAuthenticatedSessionSessionsEnumfunction_item = FunctionItem("Perform Authenticated SMB Local Session Enumeration", enum_smb_authenticated_user_enum, [username, password, "--sessions"])
    smbAuthenticatedSessionPasswordPolicyEnumfunction_item = FunctionItem("Perform Authenticated SMB Password Policy Enumeration", enum_smb_authenticated_user_enum, [username, password, "--pass-pol"])


    #Append Function Item to SMB Null Session Submenu 

    #SMB Null Session, Anonymous / Guest logon Enumeration functions
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionAccessfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionEnumAllfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionUserEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionSharesEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionPassPolEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionGroupsEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionRidBruteEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionLoggedonUsersEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionLocalGroupsEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbNullSessionSessionsEnumfunction_item)

    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestAccessfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestEnumAllfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestUserEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestSharesEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestPassPolEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestGroupsEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestRidBruteEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestLoggedonUsersEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestLocalGroupsEnumfunction_item)
    smb_null_anon_guest_enumeration_submenu.append_item(smbGuestSessionsEnumfunction_item)
   

    #Append Function Item to SMB Authentiocated Submenu
    #SMB Authenticated Enumeration functions
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionAccessfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionEnumAllfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionUserEnumfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionShareEnumfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionPasswordPolicyEnumfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionGroupEnumfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionRidBruteEnumfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionLoggedonUsersEnumfunction_item)
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionLocalGroupEnumfunction_item)   
    smb_authenticated_enumeration_submenu.append_item(smbAuthenticatedSessionSessionsEnumfunction_item)



    # Append SMB Sub Sub Menus to SMB SMB Menu
    SMB_submenu.append_item(smb_enum_hosts)
    SMB_submenu.append_item(null_anon_guest_submenu_enumeration)
    SMB_submenu.append_item(smb_authenticated_submenu_enumeration)
    enumeration_submenu.append_item(SMB_submenu_item)


    #Append Sub Menus to Main Menu Items
    menu.append_item(submenu_enumeration)
    menu.append_item(restart_function_item)
    menu.append_item(check_for_authenticated_access)
    menu.show()


def get_prologue_pretext():
    selectedTarget = "Target: \n"
    selectedUsername = "Username: \n"
    selectedPassword = "Password: \n"
    selectedNTHash = "NT Hash: \n"
    selectedDomain = "Domain: \n"
    return selectedTarget +selectedUsername +selectedPassword+ selectedNTHash +selectedDomain

# MenuItem is the base class for all items, it doesn't do anything when selected
menu_item = MenuItem("Menu Item")

premenu = ConsoleMenu("NetExec Wrapper", "By S.1.l.k.y (Maximilian Barz)\nVersion 0.2",prologue_text=get_prologue_pretext(), formatter=MenuFormatBuilder().set_title_align('center').set_subtitle_align('center').show_prologue_top_border(True).show_prologue_bottom_border(True))

# Create some items
setValuesfunction_item = FunctionItem("Set Target Values", setValuesAndStart)

# Once we're done creating them, we just add the items to the menu
premenu.append_item(setValuesfunction_item)
premenu.show()
# Finally, we call show to show the menu and allow the user to interact
