import tkinter as tk
from tkinter import filedialog, ttk
import os
from asammdf import MDF
import numpy as np
import pandas as pd
import fnmatch
import traceback

class SortingApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Sorting MDF")
        self.master.geometry("1000x800")
        self.master.configure(bg="white")

        self.top_frame = ttk.Frame(self.master)
        self.top_frame.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)

        self.center_frame = ttk.Frame(self.master)
        self.center_frame.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)

        self.button_frame = ttk.Frame(self.master)
        self.button_frame.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)

        self.select_button = ttk.Button(self.top_frame, text="Select MDF File", command=self.select_file)
        self.select_button.grid(row=0, column=0, padx=10, pady=(10, 0), sticky=tk.W)        

        self.bottom_frame=ttk.Frame(self.master)
        self.bottom_frame.grid(row=4,column=0,padx=10,pady=10,sticky=tk.W)

        self.bottom_process_frame=ttk.Frame(self.bottom_frame)
        self.bottom_process_frame.grid(row=0,column=1,padx=10,pady=10,sticky=tk.W)

        self.status_text = tk.Text(self.bottom_frame,height=10)
        self.status_text.grid(row=0,column=0,padx=5,pady=5,sticky=tk.W)

        self.process_button = ttk.Button(self.bottom_process_frame, text="Process", command=self.process)
        self.process_button.grid(row=0, column=0, padx=10, pady=(10, 0), sticky=tk.W)

        self.progress_bar = ttk.Progressbar(self.bottom_process_frame)
        self.progress_bar.grid(row=1, column=0,padx=5,pady=5,sticky=tk.W)
        
        #self.status_text.pack()
        #self.status_text.config(state='disabled')

        self.event_channel_label = ttk.Label(self.center_frame, text="Event Channel List", background="white")
        self.event_channel_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky=tk.W)
        self.event_search_var = tk.StringVar()
        self.event_search_var.trace("w", lambda *args: self.update_event_channel_list())
        self.event_search_entry = ttk.Entry(self.center_frame, textvariable=self.event_search_var, width=50)
        self.event_search_entry.grid(row=1, column=0, padx=20, pady=5, sticky=tk.W)

        self.event_channel_listbox = tk.Listbox(self.center_frame, selectmode=tk.SINGLE, width=50, height=10)
        self.event_channel_listbox.grid(row=2, column=0, padx=20, pady=5, sticky=tk.W)
        self.scrollbar = tk.Scrollbar(self.center_frame, orient="vertical", command=self.event_channel_listbox.yview)
        self.scrollbar.grid(row=2, column=2, padx=(0, 20), pady=5, sticky=tk.NS)
        self.event_channel_listbox.config(yscrollcommand=self.scrollbar.set)
        self.event_channel_listbox.bind("<<ListboxSelect>>", lambda event: self.update_event_selected_channel_list())

        self.event_selected_channel_label = ttk.Label(self.center_frame, text="Selected Event Channel:", background="white")
        self.event_selected_channel_label.grid(row=0, column=2, padx=10, pady=(10, 5), sticky=tk.W)
        self.event_selected_channel_listbox = tk.Listbox(self.center_frame, selectmode=tk.MULTIPLE, width=50, height=10)
        self.event_selected_channel_listbox.grid(row=2, column=2, padx=10, pady=5, sticky=tk.W)
        self.event_selected_scrollbar = tk.Scrollbar(self.center_frame, orient="vertical", command=self.event_selected_channel_listbox.yview)
        self.event_selected_scrollbar.grid(row=2, column=3, padx=(0, 10), pady=5, sticky=tk.NS)
        self.event_selected_channel_listbox.config(yscrollcommand=self.event_selected_scrollbar.set)


        self.channels_label = ttk.Label(self.button_frame, text="Channel List:", background="white")
        self.channels_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky=tk.W)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.update_channels_list())
        self.search_entry = ttk.Entry(self.button_frame, textvariable=self.search_var, width=50)
        self.search_entry.grid(row=1, column=0, padx=20, pady=5, sticky=tk.W)

        self.channels_listbox = tk.Listbox(self.button_frame, selectmode=tk.MULTIPLE, width=50, height=10)
        self.channels_listbox.grid(row=2, column=0, padx=20, pady=5, sticky=tk.W)
        self.scrollbar = tk.Scrollbar(self.button_frame, orient="vertical", command=self.channels_listbox.yview)
        self.scrollbar.grid(row=2, column=1, padx=(0, 20), pady=5, sticky=tk.NS)
        self.channels_listbox.config(yscrollcommand=self.scrollbar.set)
        self.channels_listbox.bind("<<ListboxSelect>>", lambda event: self.update_selected_channels_list())


        self.selected_channels_label = ttk.Label(self.button_frame, text="Selected Channels:", background="white")
        self.selected_channels_label.grid(row=0, column=1, padx=10, pady=(10, 5), sticky=tk.W)
        self.selected_channels_listbox = tk.Listbox(self.button_frame, selectmode=tk.MULTIPLE, width=50, height=10)
        self.selected_channels_listbox.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)
        self.selected_scrollbar = tk.Scrollbar(self.button_frame, orient="vertical", command=self.selected_channels_listbox.yview)
        self.selected_scrollbar.grid(row=2, column=2, padx=(0, 10), pady=5, sticky=tk.NS)
        self.selected_channels_listbox.config(yscrollcommand=self.selected_scrollbar.set)
        #self.selected_channels_listbox.bind("<<ListboxSelect>>", lambda event: self.clear_selected_channels_list())

        self.button_channel_frame = ttk.Frame(self.button_frame)
        self.button_channel_frame.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)

        self.save_channel_list_button = ttk.Button(self.button_channel_frame, text="Save Channel List", command=self.save_channel_list)
        self.save_channel_list_button.grid(row=0, column=0, padx=10, pady=(10, 0), sticky=tk.W)

        self.load_channel_list_button = ttk.Button(self.button_channel_frame, text="Load Channel List", command=self.load_channel_list)
        self.load_channel_list_button.grid(row=0, column=1, padx=10, pady=(10, 0), sticky=tk.W)

        self.event_available_channel = []
        self.event_selected_channel = []

        self.available_channels = []
        self.selected_channels = []  # 초기에 빈 리스트로 초기화
        
        self.file_path = ""
        # Add protocol handler to close the window when the user clicks the "X" button
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    def process(self):
        try:
            #파일경로가 지정되지 않거나, 선택된 채널들 없을 경우 리턴
            if not self.file_path or len(self.selected_channels) < 1 or len(self.event_selected_channel) < 1:
                return  # User didn't select a file
            data = MDF(self.file_path)

            #파일이름만 가져오기
            file_name = os.path.splitext(os.path.basename(self.file_path))[0]
            #process 버튼 disable
            self.process_button.config(state='disabled')
            #선택된 채널만 데이터 가져오기
            filter_channels = []
            filter_channels.extend(self.event_selected_channel) #이벤트 선택 채널
            filter_channels.extend(self.selected_channels) #같이 나와야할 채널들
            filter_data = data.filter(filter_channels) #필터
            #print(filter_data.channels_db)
            #필터링 된 데이터프레임
            df = filter_data.to_dataframe()
            #루프돌려서 데이터 비교 후 데이터 삭제            
            self.progress_bar.configure(maximum=df.size)
            ''' for idx, row in df.iterrows():    
                self.progress_bar["value"]=count
                self.progress_bar.update()  
                if count == 0:                
                    #tmp_data = row[self.event_selected_channel[0]]
                    tmp_data = row.iloc[0] #이벤트 변수는 필터채널리스트의 맨 앞에 저장되어 있으므로 0으로 지정
                    count += 1
                    continue           
                
                if(tmp_data == row.iloc[0]):
                    df.drop(idx,axis=0,inplace=True)                
                else:
                #  print('temp=>',tmp_data, 'value=>',row.iloc[0])
                    tmp_data = row.iloc[0]   
                count += 1
            print(df)'''   
            key = self.event_selected_channel[0]            
            df1 = df[df[key] != df[key].shift(1)] #이벤트채널의 이전데이터와 이후 데이터 비교 후 변경되면 데이터 저장
            
            #process 버튼 enable
            
            self.process_button.config(state='normal')
            
            if len(df1) < 2:
                self.status_text.config(state='normal')
                self.status_text.insert(tk.INSERT,"event selected data is not changed.\n")
                self.status_text.config(state='disabled')
                return

            self.status_text.config(state='normal')
            self.status_text.insert(tk.INSERT,str(len(df1))+" rows changed.\n")
            self.status_text.config(state='disabled')

            #csv 파일로 저장
            file_dialog = filedialog.asksaveasfilename
            file_path = file_dialog(initialfile=file_name, defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])     

            if not file_path:
                self.status_text.config(state='normal')
                self.status_text.insert(tk.INSERT,"filename is not incorrect.\n")
                self.status_text.config(state='disabled')
                return  # User didn't select a file

            df1.drop(0, inplace=True)
            df1.to_csv(file_path)
            success_msg = file_path+" csv file saved."
            self.status_text.config(state='normal')
            self.status_text.insert(tk.INSERT,success_msg+"\n")
            self.status_text.config(state='disabled')
        except Exception as e:            
            print('error:',traceback.format_exc())
            self.process_button.config(state='normal')

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[('MDF Files', '*.dat;*.mf4')])
        if not self.file_path:
            return  # User didn't select a file

        with MDF(self.file_path) as mdf:
            #self.available_channels = [ch for ch in mdf.channels_db if
            #                           ch != 'time' and '\\' not in ch and '$' not in ch and '/' not in ch]
            #self.available_channels = list(mdf.channels_db)
            self.available_channels = [ch for ch in mdf.channels_db if 
                                       ch != 'time' and '\\' in ch or '$' in ch or '/' in ch]
            #self.event_available_channel = [ch for ch in mdf.channels_db if
            #                          ch != 'time' and '\\' not in ch and '$' not in ch and '/' not in ch] 
            #self.event_available_channel = list(mdf.channels_db)       
            self.event_available_channel = [ch for ch in mdf.channels_db if 
                                       ch != 'time' and '\\' in ch or '$' in ch or '/' in ch]
            

        self.available_channels.sort(reverse=False)  # 알파벳 순으로 정렬
        self.event_available_channel.sort(reverse=False)  # 알파벳 순으로 정렬

        self.channels_listbox.delete(0, tk.END)
        for channel in self.available_channels:
            self.channels_listbox.insert(tk.END, channel)

        # Select the previously selected channels
        for i, channel in enumerate(self.available_channels):
            if channel in self.selected_channels:
                self.channels_listbox.selection_set(i)


        self.event_channel_listbox.delete(0, tk.END)
        for channel in self.event_available_channel:
            self.event_channel_listbox.insert(tk.END, channel)

        # Select the previously selected channels
        for i, channel in enumerate(self.event_available_channel):
            if channel in self.event_selected_channel:
                self.channel_listbox.selection_set(i)
          
        self.status_text.config(state='normal')
        self.status_text.insert(tk.INSERT,f" Selected file: {os.path.basename(self.file_path)}\n")
        self.status_text.config(state='disabled')
        #self.status_text.config(text=f"Selected file: {os.path.basename(self.file_path)}")

    def update_event_channel_list(self, *args):
        search_text = self.event_search_var.get().lower() #소문자변환
        
        #self.channels_listbox.delete(0, tk.END)

        matching = [i for i in range(len(self.event_available_channel)) if search_text in self.event_available_channel[i].lower()] #소문자 변환 후 데이터 있는지 확인
        
        if(len(matching) > 0): #데이터가 있으면 몇개인지 나타나고, 그중 0번째를 리스트박스에서 찾음
            self.event_channel_listbox.see(matching[0])
    '''def update_event_channel_list(self):
        event_search_text = self.event_search_var.get().lower()  # 모두 소문자로 변환
        self.event_channel_listbox.delete(0, tk.END)        

        if event_search_text.strip() == '*':
            for event_channel in self.event_available_channel:
                self.event_channel_listbox.insert(tk.END, event_channel)
        else:
            for event_channel in self.event_available_channel:
                if event_search_text in event_channel.lower():  # 모두 소문자로 변환하여 비교
                    self.event_channel_listbox.insert(tk.END, event_channel)'''

    '''def update_channels_list(self, *args):
        search_text = self.search_var.get()
        self.channels_listbox.delete(0, tk.END)

        if search_text.strip() == '*':
            for channel in self.available_channels:
                self.channels_listbox.insert(tk.END, channel)
        else:
            for channel in self.available_channels:
                if search_text in channel:
                    self.channels_listbox.insert(tk.END, channel)'''
    def update_channels_list(self, *args):
        search_text = self.search_var.get().lower() #소문자변환
        
        #self.channels_listbox.delete(0, tk.END)

        matching = [i for i in range(len(self.available_channels)) if search_text in self.available_channels[i].lower()] #소문자 변환 후 데이터 있는지 확인
        
        if(len(matching) > 0): #데이터가 있으면 몇개인지 나타나고, 그중 0번째를 리스트박스에서 찾음
            self.channels_listbox.see(matching[0])
        '''
        if search_text.strip() == '*':
            for channel in self.available_channels:
                self.channels_listbox.insert(tk.END, channel)
        else:
            for channel in self.available_channels:
                if search_text in channel:
                    self.channels_listbox.insert(tk.END, channel)'''

    def update_event_selected_channel_list(self):
        if not self.event_channel_listbox.curselection(): #리스트박스 아무것도 없을 시 클릭일 경우 리턴
            return
        self.event_selected_channel = [self.event_channel_listbox.get(i) for i in self.event_channel_listbox.curselection()]
        self.event_selected_channel_listbox.delete(0, tk.END)
        for event_channel in self.event_selected_channel:
            self.event_selected_channel_listbox.insert(tk.END, event_channel)

    '''def show_selected_event_channel(self):
        selected_event_channel_window = tk.Toplevel(self.master)
        selected_event_channel_window.title("Selected 123 Channels")

        selected_event_channel_frame = ttk.Frame(selected_event_channel_window)
        selected_event_channel_frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.NSEW)

        selected_event_channel_label = ttk.Label(selected_event_channel_frame, text="Selected 123 Channels:", background="white")
        selected_event_channel_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        selected_event_channel_listbox = tk.Listbox(selected_event_channel_frame, selectmode=tk.SINGLE, width=50, height=10)
        scrollbar = tk.Scrollbar(selected_event_channel_frame, orient="vertical", command=selected_event_channel_listbox.yview)
        selected_event_channel_listbox.config(yscrollcommand=scrollbar.set)

        selected_event_channel_listbox.grid(row=1, column=0, padx=20, pady=5, sticky=tk.NSEW)
        scrollbar.grid(row=1, column=1, padx=(0, 20), pady=5, sticky=tk.NS)'''


    '''def event_search_channel(self):
        search_term = self.event_search_var.get().lower()
        self.event_channel_listbox.delete(0, tk.END)

        for event_channel in self.event_channel:  # type: ignore
            if fnmatch.fnmatch(event_channel.lower(), search_term):
                self.event_channel_listbox.insert(tk.END, event_channel)'''

    '''def event_update_channel_list(self, *args):
        search_term = self.event_search_var.get().lower()

        self.event_channel_listbox.delete(0, tk.END)
        for event_channel in self.event_available_channel:
            if search_term in event_channel.lower():
                self.event_channel_listbox.insert(tk.END, event_channel)'''

    def update_selected_channels_list(self):        
        selected_channels = [self.channels_listbox.get(i) for i in self.channels_listbox.curselection()]

        if len(self.selected_channels) > 0:
            for item in self.selected_channels:
                if selected_channels.count(item) < 1:
                    self.selected_channels.remove(item)
            
            selected_channels = selected_channels + self.selected_channels
            selected_channels = list(set(selected_channels))

        self.selected_channels_listbox.delete(0, tk.END)
        for channel in selected_channels:
            self.selected_channels_listbox.insert(tk.END, channel)
        self.selected_channels = selected_channels
        
    def clear_selected_channels_list(self):
        self.selected_channels_listbox.delete(0, tk.END)
        self.selected_channels.clear()

    '''def show_selected_channels(self):
        selected_channels_window = tk.Toplevel(self.master)
        selected_channels_window.title("Selected Channels")

        selected_channels_frame = ttk.Frame(selected_channels_window)
        selected_channels_frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.NSEW)

        selected_channels_label = ttk.Label(selected_channels_frame, text="Selected Channels:", background="white")
        selected_channels_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        selected_channels_listbox = tk.Listbox(selected_channels_frame, selectmode=tk.SINGLE, width=50, height=10)
        scrollbar = tk.Scrollbar(selected_channels_frame, orient="vertical", command=selected_channels_listbox.yview)
        selected_channels_listbox.config(yscrollcommand=scrollbar.set)

        selected_channels_listbox.grid(row=1, column=0, padx=20, pady=5, sticky=tk.NSEW)
        scrollbar.grid(row=1, column=1, padx=(0, 20), pady=5, sticky=tk.NS)'''

    '''def search_channels(self):
        search_term = self.search_var.get().lower()
        self.channels_listbox.delete(0, tk.END)

        for channel in self.channels:  # type: ignore
            if fnmatch.fnmatch(channel.lower(), search_term):
                self.channels_listbox.insert(tk.END, channel)'''


    '''def update_channels_list(self, *args):
        search_term = self.search_var.get().lower()

        self.channels_listbox.delete(0, tk.END)
        for channel in self.available_channels:
            if search_term in channel.lower():
                self.channels_listbox.insert(tk.END, channel)'''

    def save_or_load_channel_list(self, mode):
        if mode == 'save':
            selected_channels = [self.available_channels[i] for i in self.channels_listbox.curselection()]

            if not selected_channels:
                self.status_text.config(state='normal')
                self.status_text.insert(tk.INSERT,"Please select at least one channel.\n")
                self.status_text.config(state='disabled')
                return
            file_dialog = filedialog.asksaveasfilename
            success_msg = "Selected channel list saved."
        elif mode == 'load':
            file_dialog = filedialog.askopenfilename
            success_msg = "Channel list loaded."
        else:
            raise ValueError(f"Invalid mode: {mode}")

        file_path = file_dialog(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])

        if not file_path:
            return  # User didn't select a file

        if mode == 'save':
            with open(file_path, mode='w') as file:
                for channel in selected_channels:  # type: ignore
                    file.write(f"{channel}\n")
        elif mode == 'load':
            with open(file_path, mode='r') as file:
                selected_channels = [line.strip() for line in file.readlines() if
                                     line.strip() in self.available_channels]

        self.channels_listbox.selection_clear(0, tk.END)
        for i, channel in enumerate(self.available_channels):
            if channel in selected_channels:
                self.channels_listbox.selection_set(i)

        self.selected_channels = selected_channels
        self.status_text.config(state='normal')
        self.status_text.insert(tk.INSERT,success_msg+"\n")
        self.status_text.config(state='disabled')

    def save_channel_list(self):
        self.save_or_load_channel_list('save')

    def load_channel_list(self):
        if self.channels_listbox.size() < 1: #Channel Listbox의 리스트가 없을 경우, 리턴
            self.status_text.config(state='normal')
            self.status_text.insert(tk.INSERT,"Channel List is empty.\n")
            self.status_text.config(state='disabled')    
            return

        file_path = filedialog.askopenfilename(defaultextension=".txt",
                                               filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])

        if not file_path:
            return  # User didn't select a file

        with open(file_path, mode='r') as file:
            selected_channels = [line.strip() for line in file.readlines() if line.strip() in self.available_channels]

        self.channels_listbox.selection_clear(0, tk.END)
        for i, channel in enumerate(self.available_channels):
            if channel in selected_channels:
                self.channels_listbox.selection_set(i)

        self.selected_channels = selected_channels
        self.status_text.config(state='normal')
        self.status_text.insert(tk.INSERT,"Channel list loaded.\n")
        self.status_text.config(state='disabled')

        # Add the following lines to update the selected_channels_listbox
        self.selected_channels_listbox.delete(0, tk.END)
        for channel in self.selected_channels:
            self.selected_channels_listbox.insert(tk.END, channel)

    def on_close(self):
        if tk.messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SortingApp(root)
    root.mainloop()
