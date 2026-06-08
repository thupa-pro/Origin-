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

## Generating Completions

If you have the `origin` binary built, you can regenerate completions:

```bash
origin completions bash > completions/origin.bash
origin completions zsh > completions/origin.zsh
origin completions fish > completions/origin.fish
```
