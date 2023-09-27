import typing
import numpy as np
from collections import defaultdict, deque
from enum import StrEnum
import click
from rich import print
from rich.console import Console
from rich.table import Table

ALPHABET_RUSSIAN = list("абвгдеёжзийклмнопрстуфхцчшщъыьэюя")
# ALPHABET_ENGLISH = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


class Alphabet:
    letters: list[str]
    _letter_by_index: dict[int, str]
    _index_by_letter: dict[str, int]

    def __init__(self, letters: list[str]) -> None:
        if not letters:
            raise Exception("Empty alphabet")
        self.letters = letters
        self._letter_by_index = dict(enumerate(letters))
        self._index_by_letter = dict(
            (letter, index) for index, letter in enumerate(letters)
        )
        self._vigenere_table = []
        self._vigenere_table_reversed = defaultdict(lambda: {})
        for i, _ in enumerate(letters):
            self._vigenere_table.append(self._shift_alphabet(i))
        for i, letters_row in enumerate(self._vigenere_table):
            for j, letter in enumerate(letters_row):
                self._vigenere_table_reversed[letter][
                    self.get_letter_by_index(i)
                ] = self.get_letter_by_index(j)

    def _get_letter_by_index(self, index: int) -> str:
        if index not in self._letter_by_index:
            raise Exception("Index out of range in alphabet")
        return self._letter_by_index.get(index)

    def get_letter_by_index(self, index: int) -> str:
        if index < 0:
            raise Exception("Negative index!")
        return self._letter_by_index.get(index % len(self.letters))

    def get_index_by_letter(self, letter: int) -> int:
        if letter not in self.letters_set:
            raise Exception("Letter not in alphabet")
        return self._index_by_letter.get(letter)

    @property
    def letters_set(self) -> set[str]:
        return set(self.letters)

    def _shift_alphabet(self, step: int = 1):
        return [
            self.get_letter_by_index(self.get_index_by_letter(letter) + step)
            for letter in self.letters
        ]

    def get_by_table(self, origin_letter: str, key_letter: str) -> str:
        origin = self.get_index_by_letter(origin_letter)
        key = self.get_index_by_letter(key_letter)

        return self._vigenere_table[origin][key]

    def get_by_reversed_table(self, synthesized_letter: str, key_letter: str) -> str:
        return self._vigenere_table_reversed[synthesized_letter][key_letter]

    def is_text_by_alphabet(self, text: str) -> bool:
        for letter in text:
            if letter not in set(self.letters):
                return False
        return True


class Crypter:
    @classmethod
    def _preprocess(raw_text: str) -> tuple[str, typing.Iterable[bool]]:
        is_upper_cases = np.array(
            [letter.isupper() for letter in raw_text], dtype="bool"
        )
        preprocessed_text = raw_text.lower()

        return preprocessed_text, is_upper_cases

    @classmethod
    def _postprocess(processed_text: str, is_upper_cases: typing.Iterable[bool]) -> str:
        postprocessed_text = deque()
        for letter, is_upper in zip(processed_text, is_upper_cases):
            postprocessed_text.append(letter.upper() if is_upper else letter)

        return "".join(postprocessed_text)

    @staticmethod
    def encrypt(alphabet: Alphabet, text: str, key: str) -> str:
        preprocessed_text, is_upper_cases = Crypter._preprocess(text)
        processed_text = Crypter._encrypt(alphabet, preprocessed_text, key)
        postprocessed_text = Crypter._postprocess(processed_text, is_upper_cases)
        return postprocessed_text

    @staticmethod
    def decrypt(alphabet: Alphabet, text: str, key: str) -> str:
        preprocessed_text, is_upper_cases = Crypter._preprocess(text)
        processed_text = Crypter._decrypt(alphabet, preprocessed_text, key)
        postprocessed_text = Crypter._postprocess(processed_text, is_upper_cases)
        return postprocessed_text

    @staticmethod
    def _encrypt(alphabet: Alphabet, text: str, key: str):
        enctypted_letters = []
        for index, character in enumerate(text):
            if character in alphabet.letters_set:
                enctypted_letters.append(
                    alphabet.get_by_table(character, key[index % len(key)])
                )
            else:
                enctypted_letters.append(character)
        return "".join(enctypted_letters)

    @staticmethod
    def _decrypt(alphabet: Alphabet, encrypted_text: str, key: str):
        decrypted_letters = []
        for index, character in enumerate(encrypted_text):
            if character in alphabet.letters_set:
                decrypted_letters.append(
                    alphabet.get_by_reversed_table(character, key[index % len(key)])
                )
            else:
                decrypted_letters.append(character)
        return "".join(decrypted_letters)


class FrequencyAnalizer:
    @staticmethod
    def analyze(text: str, alphabet: Alphabet) -> dict[str, int]:
        frequencies = defaultdict(lambda: 0)
        for letter in text:
            if letter in alphabet.letters_set:
                frequencies[letter] += 1
        common_count = sum(frequencies.values())
        for key, value in frequencies.items():
            frequencies[key] = value / common_count
        return frequencies


class CryptMode(StrEnum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


@click.command()
@click.option("--key", "-k", help="Ключ для шифрования/дешифрования", required=True)
@click.option(
    "--input-file",
    "-i",
    default="lab1/data/input",
    help="Путь к файлу, содержащему текст, который нужно защифровать/расшифровать",
)
@click.option(
    "--output-file",
    "-o",
    default=None,
    help="Путь к файлу, в который нужно сохранить результат операции",
)
@click.option(
    "--crypt-mode",
    "-m",
    default=CryptMode.ENCRYPT,
    type=click.Choice(mode for mode in CryptMode),
    help='Режим работы^\n\t"encrypt" - зашифровать\n\t"decrypt" - зашифровать',
    required=True,
)
@click.option(
    "--frequency-analyze",
    "-f",
    default=False,
    is_flag=True,
    help="Делать ли частотный анализ зашифрованного/расшифрованного текста",
)
@click.option(
    "--show-table", "-t", default=False, is_flag=True, help="Вывести таблица Виженера"
)
def main(
    crypt_mode: CryptMode,
    key: str,
    input_file: str,
    output_file: str | None,
    frequency_analyze: bool,
    show_table: bool,
):
    alphabet = Alphabet(ALPHABET_RUSSIAN)

    try:
        with open(input_file, "r") as file:
            text = file.read()
            if not text:
                click.echo(f"The file is empty!")
                exit(2)
    except FileNotFoundError:
        click.echo(f"The file {input_file} doesn't exist!")
        exit(1)
    # check if crypted text contains characters not from alphabet
    if uncontaining_chars := set(text) - set.union(
        alphabet.letters_set, map(str.upper, alphabet.letters_set)
    ):
        print(
            f"[bold red]Warning: the text contains character not in alphabet[bold red]:\n{uncontaining_chars}"
        )

    match crypt_mode:
        case CryptMode.ENCRYPT:
            processed = Crypter.encrypt(alphabet, text, key)
        case CryptMode.DECRYPT:
            processed = Crypter.decrypt(alphabet, text, key)
        case _:
            raise Exception("Wrong crypt-mode!")

    if output_file:
        with open(output_file, "w") as file:
            file.write(processed)
    else:
        click.echo(processed)
    console = Console()

    if frequency_analyze:
        frequencies = FrequencyAnalizer.analyze(text, alphabet)
        frequency_table = Table(show_header=True, header_style="bold magenta")
        frequency_table.add_column("Буква", style="dim", width=12)
        frequency_table.add_column("Частота")
        for letter, frequency in sorted(
            frequencies.items(), key=lambda item: item[1], reverse=True
        ):
            frequency_table.add_row(f"{letter}", f"{frequency}")
        console.print(frequency_table)

    if show_table:
        vigenere_table = Table(show_header=False, show_edge=True, show_lines=True)
        [vigenere_table.add_row(*row) for row in alphabet._vigenere_table]
        console.print(vigenere_table)


if __name__ == "__main__":
    main()
