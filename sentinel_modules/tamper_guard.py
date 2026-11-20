import os
import win32security
import ntsecuritycon as con

def harden_file_acl(file_path: str):
    if not os.path.exists(file_path):
        return

    sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
    dacl = win32security.ACL()

    admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)
    system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    users_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinUsersSid, None)

    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, system_sid)
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, admin_sid)
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        con.FILE_GENERIC_READ | con.FILE_GENERIC_EXECUTE,
        users_sid
    )

    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, sd)

def apply_tamper_protection(base_dir: str):
    for filename in ("SentinelShield.exe", "config.json"):
        target = os.path.join(base_dir, filename)
        try:
            harden_file_acl(target)
        except Exception:
            pass
