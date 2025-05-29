import tkinter as tk

class Canvas(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.text = tk.Text(self, bg='white', wrap=tk.NONE, font=("Arial", 12))
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.v_scroll = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.text.yview)
        self.v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.config(yscrollcommand=self.v_scroll.set)

        self.h_scroll = tk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.text.xview)
        self.h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.text.config(xscrollcommand=self.h_scroll.set)

        self.text.config(state=tk.DISABLED)

    def update_display(self, text):
        self.text.config(state=tk.NORMAL)
        self.text.delete(1.0, tk.END)
        self.text.insert(tk.END, text)
        self.text.config(state=tk.DISABLED)
        self.text.yview_moveto(0)