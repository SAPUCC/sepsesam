On Apple silicon you need to enable rosetta compatibility mode and add the flag `--platform linux/amd64`:
```sh
# build the image
docker build --platform linux/amd64 -t sepsesam .

# run shell in container
docker run -it --platform linux/amd64 sepsesam   
```
