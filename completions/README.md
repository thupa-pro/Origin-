# Shell Completions for Origin

## Bash

```bash
source completions/origin.bash
```

Or copy to your completions directory:
```bash
cp completions/origin.bash /usr/share/bash-completion/completions/origin
```

## Zsh

```bash
cp completions/origin.zsh /usr/share/zsh/site-functions/_origin
```

## Fish

```bash
cp completions/origin.fish ~/.config/fish/completions/
```

## Man Page

The man page at `docs/origin.1` covers all commands and options. To install:

```bash
make install-man   # requires sudo for /usr/local/share/man
```

Or manually:

```bash
gzip -c docs/origin.1 | sudo tee /usr/local/share/man/man1/origin.1.gz > /dev/null
sudo mandb -q
```

## Generating Completions

If you have the `origin` binary built, you can regenerate completions:

```bash
origin completions bash > completions/origin.bash
origin completions zsh > completions/origin.zsh
origin completions fish > completions/origin.fish
```
