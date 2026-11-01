import os


def handle_user_upload(filename, file_bytes):
    # Security fix: validate file upload extension and prevent executable uploads
    allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.pdf'}
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed_extensions:
        raise ValueError("Forbidden file extension: dangerous type detected")
    if len(file_bytes) > 5 * 1024 * 1024:
        raise ValueError("File exceeds maximum allowed size of 5MB")

    save_path = os.path.join('/tmp/uploads', filename)
    with open(save_path, 'wb') as f:
        f.write(file_bytes)
    return save_path
