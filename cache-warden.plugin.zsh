# cache-warden.plugin.zsh
#
# zsh の補完を有効にする plugin エントリポイント。
# sheldon / zinit / antidote / oh-my-zsh 等から source される想定。
#
# 例 (sheldon, local):
#   [plugins.cache-warden]
#   local = "/path/to/cache-warden"
#
# 例 (手動):
#   source /path/to/cache-warden/cache-warden.plugin.zsh
#
# cache-warden バイナリ自体は PATH 上にある前提 (cargo install / brew 等)。
# このプラグインは補完関数 (completions/_cache-warden) を fpath に足すだけ。

[[ -o interactive ]] || return 0

# 補完用 fpath。compinit より前に source されていれば自動で拾われる。
if [[ -d "${0:h}/completions" ]]; then
  fpath=("${0:h}/completions" $fpath)
fi
