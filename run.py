import libs
from structure_ui import init_and_run_UI
from constructor_ui import Ui_FTP_Brute_Forcer
# from structure_system import System_Object

if __name__ == "__main__":
    # system_info = System_Object()
    # system_info.thread_print_info()
    
    app, ui = init_and_run_UI(
        "FTP Login Brute Forcer",
        Ui_FTP_Brute_Forcer,
        UI_File_Path="ftp_cracker_UI.ui.ui"
    )
