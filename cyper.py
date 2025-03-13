import sys
import string
from PyQt6 import QtWidgets, QtCore

class PolibioCipher:
    """
    Clase que implementa el cifrado y descifrado basado en el Cuadrado de Polibio.
    
    Se consideran dos modos:
      - Modo Básico: Cada letra se reemplaza por su par de dígitos (fila y columna).
      - Modo Modificado: Se aplica una sustitución en bloques (block substitution) para aumentar
        la criptostabilidad, modificando el resultado del modo básico.
    
    La matriz se construye a partir de un alfabeto de 25 letras (se omite la 'J').
    """
    def __init__(self, substitution_offset: int = 7) -> None:
        """
        Inicializa la instancia del cifrador, generando la matriz de Polibio y los mapeos de sustitución.

        :param substitution_offset: Desplazamiento para la sustitución de bloques.
        """
        self.substitution_offset = substitution_offset
        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Se excluye la 'J'
        self.size = 5  # Matriz de 5x5
        self.letter_to_coords = {}
        self.coords_to_letter = {}
        self._create_polibio_matrix()
        self.subst_map = self._generate_substitution_mapping()
        self.inv_subst_map = {v: k for k, v in self.subst_map.items()}

    def _create_polibio_matrix(self) -> None:
        """
        Construye la matriz de Polibio y genera los diccionarios de mapeo:
        letra -> coordenadas (string) y coordenadas -> letra.
        """
        row = 1
        col = 1
        for letter in self.alphabet:
            coord = f"{row}{col}"
            self.letter_to_coords[letter] = coord
            self.coords_to_letter[coord] = letter
            col += 1
            if col > self.size:
                col = 1
                row += 1

    def _generate_substitution_mapping(self) -> dict:
        """
        Genera el mapeo de sustitución basado en un desplazamiento de los pares de coordenadas.
        
        :return: Diccionario con el mapeo original -> sustitución.
        """
        pairs = [f"{i}{j}" for i in range(1, self.size + 1) for j in range(1, self.size + 1)]
        sorted_pairs = sorted(pairs)  # Orden lexicográfico: "11", "12", ..., "55"
        offset = self.substitution_offset % len(sorted_pairs)
        rotated_pairs = sorted_pairs[offset:] + sorted_pairs[:offset]
        mapping = {orig: sub for orig, sub in zip(sorted_pairs, rotated_pairs)}
        return mapping

    def normalize_text(self, text: str) -> str:
        """
        Normaliza el texto de entrada: convierte a mayúsculas, reemplaza 'J' por 'I'
        y conserva solo las letras del alfabeto.
        
        :param text: Texto a normalizar.
        :return: Texto normalizado.
        """
        result = ""
        for ch in text.upper():
            if ch in string.ascii_uppercase:
                result += "I" if ch == "J" else ch
        return result

    def encrypt_basic(self, plaintext: str) -> str:
        """
        Cifra el texto en modo básico: cada letra se sustituye por sus coordenadas en la matriz.
        
        :param plaintext: Texto claro a cifrar.
        :return: Texto cifrado como cadena de dígitos.
        """
        text = self.normalize_text(plaintext)
        cipher = ""
        for ch in text:
            if ch in self.letter_to_coords:
                cipher += self.letter_to_coords[ch]
        return cipher

    def decrypt_basic(self, ciphertext: str) -> str:
        """
        Descifra el texto cifrado en modo básico, convirtiendo cada par de dígitos en la letra correspondiente.
        
        :param ciphertext: Texto cifrado (pares de dígitos).
        :return: Texto claro resultante.
        :raises ValueError: Si la longitud del texto cifrado es impar.
        """
        if len(ciphertext) % 2 != 0:
            raise ValueError("La longitud del texto cifrado no es válida.")
        text = ""
        for i in range(0, len(ciphertext), 2):
            pair = ciphertext[i:i+2]
            text += self.coords_to_letter.get(pair, '')
        return text

    def encrypt_modified(self, plaintext: str) -> str:
        """
        Cifra el texto en modo modificado. Se aplica primero el cifrado básico y luego una
        sustitución en bloques para aumentar la criptostabilidad.
        
        :param plaintext: Texto claro a cifrar.
        :return: Texto cifrado modificado.
        """
        basic = self.encrypt_basic(plaintext)
        modified = ""
        for i in range(0, len(basic), 2):
            pair = basic[i:i+2]
            modified += self.subst_map.get(pair, pair)
        return modified

    def decrypt_modified(self, ciphertext: str) -> str:
        """
        Descifra el texto cifrado en modo modificado. Primero invierte la sustitución en bloques y
        luego aplica el descifrado básico.
        
        :param ciphertext: Texto cifrado modificado.
        :return: Texto claro descifrado.
        """
        reversed_text = ""
        for i in range(0, len(ciphertext), 2):
            pair = ciphertext[i:i+2]
            reversed_text += self.inv_subst_map.get(pair, pair)
        return self.decrypt_basic(reversed_text)

class PolibioCipherGUI(QtWidgets.QMainWindow):
    """
    Interfaz gráfica de usuario para la aplicación de cifrado/descifrado usando el Cuadrado de Polibio.
    
    La interfaz permite:
      - Seleccionar el modo de operación (Básico o Modificado).
      - Ingresar el texto a cifrar o descifrar.
      - Visualizar el resultado del proceso.
      - Ejecutar una batería de pruebas (casos de control) para comprobar el correcto funcionamiento.
    """
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Cifrado Cuadrado de Polibio")
        self.resize(700, 500)
        self.cipher = PolibioCipher(substitution_offset=7)
        self._init_ui()

    def _init_ui(self) -> None:
        """
        Configura los elementos y el layout de la interfaz.
        """
        central_widget = QtWidgets.QWidget(self)
        self.setCentralWidget(central_widget)
        
        main_layout = QtWidgets.QVBoxLayout(central_widget)
        
        # Selección de modo de cifrado
        mode_layout = QtWidgets.QHBoxLayout()
        mode_label = QtWidgets.QLabel("Modo:")
        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["Básico", "Modificado"])
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        main_layout.addLayout(mode_layout)
        
        # Área de entrada
        input_group = QtWidgets.QGroupBox("Texto de Entrada")
        input_layout = QtWidgets.QVBoxLayout()
        self.input_text = QtWidgets.QTextEdit()
        self.input_text.setPlaceholderText(
            "Ingrese el texto a cifrar/descifrar.\nSe considerarán solo letras; 'J' se reemplaza por 'I'."
        )
        input_layout.addWidget(self.input_text)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)
        
        # Botones de acción
        button_layout = QtWidgets.QHBoxLayout()
        self.encrypt_button = QtWidgets.QPushButton("Cifrar")
        self.decrypt_button = QtWidgets.QPushButton("Descifrar")
        self.test_button = QtWidgets.QPushButton("Ejecutar Tests")
        button_layout.addWidget(self.encrypt_button)
        button_layout.addWidget(self.decrypt_button)
        button_layout.addWidget(self.test_button)
        main_layout.addLayout(button_layout)
        
        # Área de salida
        output_group = QtWidgets.QGroupBox("Resultado")
        output_layout = QtWidgets.QVBoxLayout()
        self.output_text = QtWidgets.QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("El resultado se mostrará aquí...")
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)
        
        # Conectar acciones a los botones
        self.encrypt_button.clicked.connect(self._on_encrypt)
        self.decrypt_button.clicked.connect(self._on_decrypt)
        self.test_button.clicked.connect(self._run_tests)

    def _on_encrypt(self) -> None:
        """
        Maneja la acción del botón "Cifrar". Obtiene el texto de entrada, aplica el cifrado según el modo
        seleccionado y muestra el resultado.
        """
        text = self.input_text.toPlainText().strip()
        if not text:
            QtWidgets.QMessageBox.warning(self, "Advertencia", "El campo de texto está vacío.")
            return
        
        mode = self.mode_combo.currentText()
        try:
            if mode == "Básico":
                result = self.cipher.encrypt_basic(text)
            else:
                result = self.cipher.encrypt_modified(text)
            self.output_text.setPlainText(result)
        except Exception as ex:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error al cifrar: {ex}")

    def _on_decrypt(self) -> None:
        """
        Maneja la acción del botón "Descifrar". Obtiene el texto de entrada, aplica el descifrado según el modo
        seleccionado y muestra el resultado.
        """
        text = self.input_text.toPlainText().strip()
        if not text:
            QtWidgets.QMessageBox.warning(self, "Advertencia", "El campo de texto está vacío.")
            return
        
        mode = self.mode_combo.currentText()
        try:
            if mode == "Básico":
                result = self.cipher.decrypt_basic(text)
            else:
                result = self.cipher.decrypt_modified(text)
            self.output_text.setPlainText(result)
        except Exception as ex:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error al descifrar: {ex}")

    def _run_tests(self) -> None:
        """
        Ejecuta 10 casos de prueba predefinidos para verificar la corrección de los algoritmos de cifrado y descifrado.
        Muestra los resultados en un cuadro de diálogo.
        """
        test_cases = [
            "HELLO",
            "WORLD",
            "POLIBIO",
            "CIFRADO",
            "ENCRIPTACION",
            "PYQTINTERFACE",
            "TESTCASE",
            "ALFABETO",
            "SEGURIDAD",
            "MODIFICACION"
        ]
        
        results = []
        for test in test_cases:
            normalized = self.cipher.normalize_text(test)
            basic_enc = self.cipher.encrypt_basic(test)
            basic_dec = self.cipher.decrypt_basic(basic_enc)
            basic_status = "OK" if basic_dec == normalized else "Fallo"
            
            mod_enc = self.cipher.encrypt_modified(test)
            mod_dec = self.cipher.decrypt_modified(mod_enc)
            mod_status = "OK" if mod_dec == normalized else "Fallo"
            
            results.append(
                f"Test: {test}\n  Básico: {basic_status}\n  Modificado: {mod_status}\n"
            )
        
        results_text = "\n".join(results)
        QtWidgets.QMessageBox.information(self, "Resultados de Pruebas", results_text)

def main() -> None:
    """
    Función principal que inicializa la aplicación y muestra la ventana principal.
    """
    app = QtWidgets.QApplication(sys.argv)
    window = PolibioCipherGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
