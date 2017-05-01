
alphabet_lower = ["a",
                  "b",
                  "c",
                  "d",
                  "e",
                  "f",
                  "g",
                  "h",
                  "i",
                  "j",
                  "k",
                  "l",
                  "m",
                  "n",
                  "o",
                  "p",
                  "q",
                  "r",
                  "s",
                  "t",
                  "u",
                  "v",
                  "w",
                  "x",
                  "y",
                  "z"]


def concatenate_char(c, i, text):
    if c.islower():
        return text + alphabet_lower[i]
    else:
        return text + alphabet_lower[i].upper()


def rot13(text):
    rot13_text = ""
    for c in text:
        c_lower = c.lower()
        if c_lower in alphabet_lower:
            i = alphabet_lower.index(c_lower)
            if i < 13:
                rot13_text = concatenate_char(c, i + 13, rot13_text)
            else:
                re = len(alphabet_lower) - i
                rot13_text = concatenate_char(c, 13 - re, rot13_text)
        else:
            rot13_text = rot13_text + c
    return rot13_text