```shell
docker buildx build --load -t sorrygo-decryptor-centos:7 .
mkdir dist
docker run -v ../:/app/src -v ./dist/:/app/dist sorrygo-decryptor-centos:7 bash -c "source .venv/bin/activate && pyinstaller --onefile src/decryptor.py"
```