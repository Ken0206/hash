# code from Grok  2025/02/28
# python.exe -m pip install --upgrade pip
# pip install PyQt6 cryptography pyinstaller
# pyinstaller --onefile --noconsole ???.py

import sys
import hashlib
import hmac
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QLabel, QLineEdit, QComboBox,
                            QCheckBox, QPushButton, QTextEdit, QFileDialog)
from PyQt6.QtCore import Qt

class HashCalculator(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hash 計算機")
        self.setGeometry(100, 100, 500, 450)

        # 創建主 widget 和布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # 輸入方式選擇（下拉式選單）
        input_type_layout = QHBoxLayout()
        input_type_label = QLabel("輸入方式:")
        self.input_type_combo = QComboBox()
        self.input_type_combo.addItems(['純文字', '檔案'])
        self.input_type_combo.currentTextChanged.connect(self.toggle_input_type)
        input_type_layout.addWidget(input_type_label)
        input_type_layout.addWidget(self.input_type_combo)
        layout.addLayout(input_type_layout)

        # 文字輸入區域
        self.text_layout = QVBoxLayout()
        text_label = QLabel("輸入文字:")
        self.input_text = QLineEdit()
        self.text_layout.addWidget(text_label)
        self.text_layout.addWidget(self.input_text)
        self.text_widget = QWidget()
        self.text_widget.setLayout(self.text_layout)
        layout.addWidget(self.text_widget)

        # 檔案輸入區域
        self.file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.file_path.setAcceptDrops(True)
        self.file_path.dragEnterEvent = self.dragEnterEvent
        self.file_path.dropEvent = self.dropEvent
        self.file_button = QPushButton("選擇檔案")
        self.file_button.clicked.connect(self.select_file)
        self.file_layout.addWidget(self.file_path)
        self.file_layout.addWidget(self.file_button)
        self.file_widget = QWidget()
        self.file_widget.setLayout(self.file_layout)
        self.file_widget.setVisible(False)
        layout.addWidget(self.file_widget)

        # 演算法選擇
        algo_layout = QHBoxLayout()
        algo_label = QLabel("選擇演算法:")
        self.algo_combo = QComboBox()
        self.algo_combo.addItems(['SHA256', 'SHA512', 'MD5', 'SHA1'])
        algo_layout.addWidget(algo_label)
        algo_layout.addWidget(self.algo_combo)
        layout.addLayout(algo_layout)

        # HMAC 選項
        hmac_layout = QHBoxLayout()
        self.hmac_check = QCheckBox("使用 HMAC")
        self.hmac_key = QLineEdit()
        self.hmac_key.setPlaceholderText("輸入 HMAC 密鑰")
        self.hmac_key.setEnabled(False)
        self.hmac_check.stateChanged.connect(self.toggle_hmac)
        hmac_layout.addWidget(self.hmac_check)
        hmac_layout.addWidget(self.hmac_key)
        layout.addLayout(hmac_layout)

        # 計算按鈕
        self.calc_button = QPushButton("計算 Hash")
        self.calc_button.clicked.connect(self.calculate_hash)
        layout.addWidget(self.calc_button)

        # 結果顯示
        result_label = QLabel("結果:")
        self.result_display = QTextEdit()
        self.result_display.setReadOnly(True)
        layout.addWidget(result_label)
        layout.addWidget(self.result_display)

        layout.addStretch()

    def toggle_input_type(self, input_type):
        """根據下拉選單切換文字輸入和檔案輸入的顯示"""
        is_text = input_type == '純文字'
        self.text_widget.setVisible(is_text)
        self.file_widget.setVisible(not is_text)

    def toggle_hmac(self, state):
        """啟用/禁用 HMAC 密鑰輸入框"""
        self.hmac_key.setEnabled(state == Qt.CheckState.Checked.value)

    def select_file(self):
        """打開檔案選擇對話框"""
        file_path, _ = QFileDialog.getOpenFileName(self, "選擇檔案", "", "所有檔案 (*)")
        if file_path:
            self.file_path.setText(file_path)

    def dragEnterEvent(self, event):
        """處理拖曳進入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        """處理放下事件"""
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            self.file_path.setText(file_path)
            event.acceptProposedAction()

    def calculate_hash(self):
        """計算 hash 值的主函數並直接複製到剪貼簿"""
        algorithm = self.algo_combo.currentText().lower()
        use_hmac = self.hmac_check.isChecked()
        hmac_key = self.hmac_key.text() if use_hmac else None
        input_type = self.input_type_combo.currentText()

        if input_type == '純文字':
            text = self.input_text.text()
            if not text:
                self.result_display.setText("請輸入文字！")
                return
            data = text.encode('utf-8')
        else:
            file_path = self.file_path.text()
            if not file_path:
                self.result_display.setText("請選擇檔案或拖曳檔案進來！")
                return
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
            except Exception as e:
                self.result_display.setText(f"讀取檔案失敗: {str(e)}")
                return

        try:
            result = self.compute_hash(data, algorithm, hmac_key)
            self.result_display.setText(result)
            # 直接複製到剪貼簿，無提示
            clipboard = QApplication.clipboard()
            clipboard.setText(result)
        except Exception as e:
            self.result_display.setText(f"錯誤: {str(e)}")

    def compute_hash(self, data, algorithm, hmac_key=None):
        """執行實際的 hash 計算"""
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }

        if algorithm not in hash_functions:
            return "不支援的演算法"

        if hmac_key:
            key_bytes = hmac_key.encode('utf-8')
            hash_obj = hmac.new(
                key=key_bytes,
                msg=data,
                digestmod=hash_functions[algorithm]
            )
        else:
            hash_obj = hash_functions[algorithm]()
            hash_obj.update(data)

        return hash_obj.hexdigest()

def main():
    app = QApplication(sys.argv)
    window = HashCalculator()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()