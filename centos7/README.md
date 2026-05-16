```shell
mkdir dist
docker run \
  -v ../://tmp/src \
  -v ./dist/:/tmp/dist \
  --user $(id -u):$(id -g) \
  centos/python-38-centos7 \
  bash -c "cd /tmp && python3 -m venv .venv && source .venv/bin/activate && pip install pyinstaller 'cryptography<47' && pip install -r src/requirements.txt && pyinstaller --onefile src/decryptor.py"
```