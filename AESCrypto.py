import tkinter as tk
from AES_Code import BruteForceAttack, aes_Encrypt, aes_Decrypt, \
    bytes_to_hex, string_to_hex, hex_to_string


class AESCrypto(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("META CRYPTO")
        self.geometry("800x520")

        # Variaveis
        self.text = tk.StringVar()  # Texto a ser Encript ou Decript
        self.key = tk.StringVar()  # Chave de Crypto
        self.message = tk.StringVar()  # Mensagem a ser exibida

        # Background
        self.background = tk.PhotoImage(file="eyetech2.png")  # Imagem de fundo
        self.bglabel = tk.Label(self, image=self.background)  # Colocar a imagem num Label
        self.bglabel.place(relx=0.495, rely=0.5, anchor="center")  # Posição do Label

        # Frames
        entryFrames = []  # Caixa dos Labels dos Campos de entrada

        # Frame 1 - Texto
        frame1 = tk.Frame(self, bg='black')

        labelText = tk.Label(frame1, text='Texto', bg='black', fg='white')
        self.entryText = tk.Entry(frame1, bg='darkgray', width=16)

        labelText.pack(side="left", padx=.5, pady=.5)
        self.entryText.pack(side="left", padx=1, pady=1)

        saveBtt1 = tk.Button(frame1, text="Save",
                             bg='gray', padx=4, width=4,
                             command=lambda: self.getText())
        saveBtt1.pack()
        entryFrames.append(frame1)

        # Frame 2 - Chave
        frame2 = tk.Frame(self, bg='black')

        labelKey = tk.Label(frame2, text='Chave', bg='black', fg='white')
        self.entryKey = tk.Entry(frame2, bg='darkgray', width=16)

        labelKey.pack(side="left", padx=.5, pady=.5)
        self.entryKey.pack(side="left", padx=1, pady=1)

        saveBtt2 = tk.Button(frame2, text="Save",
                             bg='gray', padx=4, width=4,
                             command=lambda: self.getKey())
        saveBtt2.pack()
        entryFrames.append(frame2)

        # Posição Frame 1 e 2
        for i, frame in enumerate(entryFrames):
            frame.place(relx=0.5, rely=0.375 + i * 0.08, anchor="center")

        # Frames Botões
        bttFrame1 = tk.Frame(self, bg='black')
        bttFrame2 = tk.Frame(self, bg='black')

        encryptBtt = tk.Button(bttFrame1, text="Criptografar",
                               bg='blue', fg='white', width=9,
                               command=lambda: self.criptografar())
        decryptBtt = tk.Button(bttFrame1, text="Decifrar",
                               bg='red', fg='white', width=9,
                               command=lambda: self.decifrar())
        testBtt = tk.Button(bttFrame2, text="Testar",
                            bg='green', fg='white', width=9,
                            command=lambda: self.testar())

        encryptBtt.pack(side="left", padx=4)
        decryptBtt.pack(side="left", padx=4)
        testBtt.pack(side="left", padx=4)

        bttFrame1.place(relx=0.5, rely=0.55, anchor="center")
        bttFrame2.place(relx=0.5, rely=0.625, anchor="center")

        # Frame Mensagem
        frame3 = tk.Frame(self, bg='black')
        labelMsg = tk.Label(frame3, text='Mensagem', bg='black', fg='white')
        labelMsg.pack(padx=.5, pady=.5)
        frame3.place(relx=.5, rely=.75, anchor='center')

        frame4 = tk.Frame(self, bg='black')
        self.entryMsg = tk.Entry(frame4, bg='darkgray', width=35,
                                 textvariable=self.message, state='readonly')
        self.entryMsg.pack(side="left", padx=.5, pady=.5)
        frame4.place(relx=.5, rely=.79, anchor="center")

        # Largura de Frames
        self.update_idletasks()
        max_width = max(frame.winfo_width() for frame in entryFrames)
        for frame in entryFrames:
            frame.config(width=max_width)
        bttFrameWidth = bttFrame1.winfo_width()
        bttFrame1.config(width=bttFrameWidth)
        bttFrame2.config(width=bttFrameWidth)

    # Get Entry Text
    def getText(self):
        """Pegar o texto inserido pelo Usuário"""
        texto = self.entryText.get()
        self.text.set(texto)

    # Get Entry Key
    def getKey(self):
        """Pegar a chave inserida pelo Usuário"""
        chave = self.entryKey.get()
        self.key.set(chave)

    # Atualizar Field Mensagem
    def updateMSG(self, msg):
        """Atualizar Field Mensagem"""
        self.message.set(msg)
        self.entryMsg.config(state='normal')
        self.entryMsg.delete(0, tk.END)
        self.entryMsg.insert(0, msg)
        self.entryMsg.config(state='readonly')

    # Criptografar
    def criptografar(self):
        try:
            texto = self.text.get()
            chave = self.key.get()
            inputblock = bytearray.fromhex(string_to_hex(texto))
            key = bytearray.fromhex(string_to_hex(chave))
            encrypted_bytes = aes_Encrypt(inputblock, key)
            hex_string = bytes_to_hex(encrypted_bytes)
            self.updateMSG(hex_string)
        except Exception as e:
            self.updateMSG(str(e))
            print(e)

    # Decriptografar
    def decifrar(self):
        try:
            if not hasattr(self, 'text'):
                raise ValueError("Nenhum dado criptografado armazenado")
            texto = self.text.get()
            chave = self.key.get()
            key = bytearray.fromhex(string_to_hex(chave))
            txt = bytearray.fromhex(texto)
            decrypted_bytes = aes_Decrypt(txt, key)
            result = hex_to_string(bytes_to_hex(decrypted_bytes))
            self.updateMSG(result)
        except Exception as e:
            self.updateMSG(str(e))
            # print(e)

    # Teste Brute Force
    def testar(self):
        try:
            texto = self.text.get()
            txt = bytearray.fromhex(texto)
            result = BruteForceAttack(txt)
            self.updateMSG(result)
        except Exception as e:
            self.updateMSG(str(e))


code = AESCrypto()
code.mainloop()
