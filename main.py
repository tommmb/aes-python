import hashlib
import tkinter as tk
from tkinter import messagebox
import mysql.connector
import bcrypt
import base64
import re


# import hashlib

def main():
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        passwd="root",
        database='project'
    )

    cursor = db.cursor()

    root = App()
    root.mainloop()


class App(tk.Tk):
    def __init__(self):
        self.grey = '#CDCDCD'
        self.db = mysql.connector.connect(
            host="localhost",
            user="root",
            passwd="root",
            database='project'
        )

        self.cursor = self.db.cursor()

        tk.Tk.__init__(self)
        self.geometry('900x600')
        self.resizable(0, 0)
        self.title('Project Name')
        self.configure(bg=self.grey)
        self._frame = None
        self.switch_frame(LoginPage)

    def switch_frame(self, frame_class):
        new_frame = frame_class(self)
        if self._frame is not None:
            self._frame.destroy()
        self._frame = new_frame
        self._frame.pack()


class LoginPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)

        """ Title """
        title_label = tk.Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1, relief='solid')
        title_label.grid(column=1, row=0, pady=80, ipadx=10, ipady=5)

        """ Email """
        email = tk.StringVar()
        email_label = tk.Label(self, text='Email:', bg=grey, font=('Arial', 10)) \
            .grid(column=0, row=1, pady=10)
        email_field = tk.Entry(self, textvariable=email, width=37, font=('Arial', 12))
        email_field.configure(highlightbackground=grey)
        email_field.grid(column=1, row=1, pady=10)

        """ Password """
        password = tk.StringVar()
        password_label = tk.Label(self, text='Password:', bg=grey, font=('Arial', 10)) \
            .grid(column=0, row=2, pady=5)
        password_field = tk.Entry(self, textvariable=password, show='•', width=37, font=('Arial', 12))
        password_field.grid(column=1, row=2, pady=10)

        """ Login Button """
        login_button = tk.Button(self, text='Login', bg='#A9D7FF', font=('Arial', 11),
                                 command=lambda email=email_field, password=password_field: self.login(email, password))

        login_button.configure(highlightbackground=grey)
        login_button.grid(column=1, row=3, ipadx=145, pady=20)

        """ No Account / Register  """
        register_label = tk.Label(self, text="Don't have an account?", bg=grey, font=('Arial', 10)) \
            .grid(column=1, row=4, pady=10, columnspan=2)

        register_button = tk.Button(self, text='Register', command=lambda: master.switch_frame(RegisterPage), width=10,
                                    font=('Arial', 10))
        register_button.configure(highlightbackground=grey)
        register_button.grid(column=1, row=5)

    def login(self, _email, _password):
        email, password = _email.get().strip(), _password.get().strip()
        # if len(password) < 1:
        #     messagebox.showwarning('Error', 'Please enter a valid email.')
        #     return

        regex = re.search("^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
        if regex is None:
            messagebox.showwarning('Error', 'Please enter an email.')
            return
        try:
            email = regex.group(0)
            salt_query = 'SELECT salt FROM Users WHERE email = "%s";' % email
            salt = self.master.cursor.execute(salt_query)
            salt = self.master.cursor.fetchone()[0]

            hashed = bcrypt.hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')
            query = 'SELECT * from Users WHERE email = "%s" AND password = "%s" LIMIT 1;' % (email, hashed)
            self.master.cursor.execute(query)
            result = self.master.cursor.fetchone()

            messagebox.showinfo('Welcome', f'Welcome, {result[4]} {result[5]}')
            # print('welcome, ' + result[4] + ' ' + result[5])

        except Exception:
            messagebox.showwarning('Error', 'Incorrect email or password')
            return


class RegisterPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)

        """ Title """
        title_label = tk.Label(self, text='Project Name', font=('Arial', 32), bg=grey, borderwidth=1,
                               relief='solid')
        title_label.grid(column=0, row=0, pady=80, ipadx=10, ipady=5, columnspan=4)

        """ Email """
        email = tk.StringVar()

        email_label = tk.Label(self, text='Email:', bg=grey, font=('Arial', 10)).grid(column=0, row=1, pady=10, padx=10)

        email_field = tk.Entry(self, textvariable=email, width=25, font=('Arial', 12))
        email_field.configure(highlightbackground=grey)
        email_field.grid(column=1, row=1, pady=10)

        """ Password """
        password = tk.StringVar()

        password_label = tk.Label(self, text='Password:', bg=grey, font=('Arial', 10)).grid(column=0, row=2, pady=5,
                                                                                            padx=10)

        password_field = tk.Entry(self, textvariable=password, show='•', width=25, font=('Arial', 12))
        password_field.configure(highlightbackground=grey)
        password_field.grid(column=1, row=2, pady=10)

        """ Confirm Password"""
        confirm_password = tk.StringVar()

        confirm_password_label = tk.Label(self, text='Confirm Password:', bg=grey, font=('Arial', 10))
        confirm_password_label.grid(column=0, row=3, pady=10, padx=10)

        confirm_password_field = tk.Entry(self, textvariable=confirm_password, show='•', width=25, font=('Arial', 12))
        confirm_password_field.configure(highlightbackground=grey)
        confirm_password_field.grid(column=1, row=3, pady=10)

        """ First Name"""
        first_name = tk.StringVar()

        first_name_label = tk.Label(self, text='First Name:', bg=grey, font=('Arial', 10))
        first_name_label.grid(column=2, row=1, padx=20)

        first_name_field = tk.Entry(self, textvariable=first_name, width=25, font=('Arial', 12))
        first_name_field.configure(highlightbackground=grey)
        first_name_field.grid(column=3, row=1, padx=5, pady=10)

        """ Last Name """
        last_name = tk.StringVar()

        last_name_label = tk.Label(self, text='Last Name:', bg=grey, font=('Arial', 10))
        last_name_label.grid(column=2, row=2, padx=20)

        last_name_field = tk.Entry(self, textvariable=last_name, width=25, font=('Arial', 12))
        last_name_field.configure(highlightbackground=grey)
        last_name_field.grid(column=3, row=2, padx=5, pady=10)

        """ Register Button"""

        register_button = tk.Button(self, text='Register', bg='#A9D7FF', width=30, font=('Arial', 11),
                                    command=lambda _email=email_field,
                                                   _password=password_field,
                                                   _confirm_password=confirm_password_field,
                                                   _first_name=first_name_field,
                                                   _last_name=last_name_field:
                                    self.register(_email, _password, _confirm_password,
                                                  _first_name, _last_name))
        register_button.configure(highlightbackground=grey)
        register_button.grid(column=0, row=4, columnspan=4, pady=20)

        login_label = tk.Label(self, text="Already have an account?", bg=grey, font=('Arial', 10))
        login_label.grid(column=0, row=5, pady=5, columnspan=4)
        login_button = tk.Button(self, text='Login', command=lambda: master.switch_frame(LoginPage),
                                 font=('Arial', 10), width=6)
        login_button.configure(highlightbackground=grey)
        login_button.grid(column=0, row=6, pady=5, columnspan=4)

    def register(self, email, password, confirm_password, first_name, last_name):
        email, password, confirm_password, first_name, last_name = \
            email.get().strip(), password.get().strip(), confirm_password.get().strip(), first_name.get().strip(), last_name.get().strip()

        if len(email) < 1:
            print('please enter a valid email')
            return
        elif len(first_name) < 1:
            print('please enter your first name')
            return
        elif len(last_name) < 1:
            print('please enter your last name')
            return
        elif len(confirm_password) < 1 or len(password) < 1:
            print('passwords do not match')
            return
        elif confirm_password != password:
            print('passwords do not match')
            return

        regex = re.search("^[^@\s]+@[^@\s]+\.[^@\s]+$", email)
        if regex is None:
            print('please enter a valid email')
            return
        try:
            email = regex.group(0)
            query = 'SELECT * FROM Users WHERE email = "%s"' % email
            self.master.cursor.execute(query)
            result = self.master.cursor.fetchone()

            if result is not None:
                print('a user already exists with that email')
                return
        except Exception:
            print('please enter a valid email1')
            return

        salt = bcrypt.gensalt(rounds=10).decode('utf-8')
        hashed = bcrypt.hashpw(bytes(password, 'utf-8'), salt.encode('utf-8')).decode('utf-8')

        try:
            query = 'INSERT INTO Users (email, password, salt, first_name, last_name) ' \
                    'VALUES ("%s", "%s", "%s", "%s", "%s");' % (email, hashed, salt, first_name, last_name)
            print(query)
            self.master.cursor.execute(query)
            self.master.db.commit()

            print('successfully registered')
        except Exception:
            print('something went wrong')


class MainPage(tk.Frame):
    def __init__(self, master):
        grey = master.grey
        tk.Frame.__init__(self, master, bg=grey)



if __name__ == '__main__':
    main()
