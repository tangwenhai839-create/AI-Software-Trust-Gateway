"""Benign Image Resizer Tool
A simple image processing script using Pillow.
"""
from PIL import Image


def resize_image(input_path: str, output_path: str, width: int, height: int):
    """Resize an image to target dimensions."""
    with Image.open(input_path) as img:
        resized = img.resize((width, height))
        resized.save(output_path)
        return output_path


if __name__ == "__main__":
    print("Image resizer loaded.")
