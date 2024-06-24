You can use the devcontainer based on the Dockerfile in this repo.

1. Open Command Palette in VSCode (CRTL + SHIFT + P || View -> Command Palette)
1. Run: `Dev Containers: Reopen in container`
1. ...this will build the container, install sesam, etc. and start it up. This can take some minutes.

Once started completely, you should be able to visit https://localhost:11401/sep/ui/dashboard in your browser. You can also use for example `curl -kI https://localhost:11401/sep/ui/dashboard` to check the connection from CLI and do some tests against the API.
