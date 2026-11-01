import os

def handle_user_upload(filename, file_bytes):
    save_path = os.path.join('/tmp/uploads', filename)
    with open(save_path, 'wb') as f:
        f.write(file_bytes)
    return save_path
