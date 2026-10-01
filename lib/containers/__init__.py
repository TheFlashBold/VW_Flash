"""Self-addressed flash containers (SGO, BCB/Aisin ODX, ...) whose layout comes
from the container itself rather than a fixed FlashInfo. Each module exposes
``extract_container(path, out_dir=None) -> (image, file_name)``; VW_Flash.py
calls it for --action extract_frf."""
