"""Тексты окна: оба языка полны, выбор языка детерминирован."""
import os
import unittest
from unittest.mock import patch
from sealsnap.gui import TEXTS, language


class GuiTextTests(unittest.TestCase):
    def test_both_languages_have_the_same_complete_keys(self):
        self.assertEqual(set(TEXTS), {'en', 'ru'})
        self.assertEqual(set(TEXTS['en']), set(TEXTS['ru']))
        for lang, texts in TEXTS.items():
            for key, value in texts.items():
                with self.subTest(lang=lang, key=key):
                    self.assertTrue(value.strip())
        self.assertTrue(all(v.isascii() for k, v in TEXTS['en'].items() if k not in ('folder', 'verify', 'closing')))

    def test_environment_override(self):
        for value, expected in (('en', 'en'), ('RU', 'ru'), (' ru ', 'ru')):
            with self.subTest(value=value), patch.dict(os.environ, {'SEALSNAP_LANG': value}):
                self.assertEqual(language(), expected)

    def test_unknown_override_falls_back_to_a_supported_language(self):
        with patch.dict(os.environ, {'SEALSNAP_LANG': 'xx'}):
            self.assertIn(language(), TEXTS)


if __name__ == '__main__':
    unittest.main()
