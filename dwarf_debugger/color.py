import os


class Color:
    """
    Colorify class.
    by @hugsy
    https://github.com/hugsy/gef/blob/master/gef.py#L325
    """
    colors = {
        "normal": "\033[0m",
        "gray": "\033[1;38;5;240m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "pink": "\033[35m",
        "bold": "\033[1m",
        "underline": "\033[4m",
        "underline_off": "\033[24m",
        "highlight": "\033[3m",
        "highlight_off": "\033[23m",
        "blink": "\033[5m",
        "blink_off": "\033[25m",
    }

    @staticmethod
    def colorify(text, attrs):
        if os.name == 'nt':
            return text

        """Color a text following the given attributes."""
        colors = Color.colors
        msg = [colors[attr] for attr in attrs.split() if attr in colors]
        msg.append(text)
        if colors["highlight"] in msg:   msg.append(colors["highlight_off"])
        if colors["underline"] in msg:   msg.append(colors["underline_off"])
        if colors["blink"] in msg:       msg.append(colors["blink_off"])
        msg.append(colors["normal"])
        return "".join(msg)
