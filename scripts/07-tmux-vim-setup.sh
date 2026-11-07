#!/usr/bin/env bash
set -euo pipefail

# Script 07: Setup tmux (vi-mode, infinite scroll, modern colors) & vim
# Configures a full developer environment for terminal power users.

ADMIN_USER="${1:-${ADMIN_USER:-admin}}"

echo "==> [07] Installing tmux and vim..."
apt-get update -qq
apt-get install -y -qq tmux vim xclip

configure_user_env() {
    local target_user="$1"
    local user_home="$2"

    echo "==> [07] Configuring tmux & vim for '${target_user}'..."

    # 1. ~/.tmux.conf
    cat <<'EOF' > "${user_home}/.tmux.conf"
# ==============================================================================
# TMUX CONFIGURATION (Vim-mode, Modern Theme, Infinite Scroll)
# ==============================================================================

# Enable true color support
set -g default-terminal "xterm-256color"
set -ga terminal-overrides ",*256col*:Tc"

# No delay for escape key press (critical for Vim responsiveness)
set -s escape-time 0

# Start window and pane numbering at 1, renumber on close
set -g base-index 1
setw -g pane-base-index 1
set -g renumber-windows on

# Infinite scroll history (100,000 lines)
set -g history-limit 100000

# Mouse support (scroll with wheel, click to select pane/tab, resize)
set -g mouse on

# ------------------------------------------------------------------------------
# VI-MODE & VIM-LIKE KEYBINDINGS
# ------------------------------------------------------------------------------
setw -g mode-keys vi

# Vim-like pane navigation (Prefix + h/j/k/l)
bind h select-pane -L
bind j select-pane -D
bind k select-pane -U
bind l select-pane -R

# Vim-like pane resizing (Prefix + H/J/K/L)
bind -r H resize-pane -L 5
bind -r J resize-pane -D 5
bind -r K resize-pane -U 5
bind -r L resize-pane -R 5

# Intuitive splits in current directory
bind | split-window -h -c "#{pane_current_path}"
bind - split-window -v -c "#{pane_current_path}"
bind c new-window -c "#{pane_current_path}"

# Vi copy mode keybindings (v to select, y to copy)
bind -T copy-mode-vi v send-keys -X begin-selection
bind -T copy-mode-vi y send-keys -X copy-selection-and-cancel

# Reload config shortcut (Prefix + r)
bind r source-file ~/.tmux.conf \; display-message "Tmux config reloaded!"

# ------------------------------------------------------------------------------
# MODERN TASTEFUL STATUS BAR & PANE THEME (Tokyo Night / Catppuccin palette)
# ------------------------------------------------------------------------------
set -g status-position bottom
set -g status-interval 5
set -g status-style "bg=#1e1e2e,fg=#cdd6f4"

# Left: Session name pill
set -g status-left-length 40
set -g status-left "#[bg=#89b4fa,fg=#11111b,bold] #S #[bg=#1e1e2e,fg=#89b4fa] "

# Right: Date, Time and Hostname pill
set -g status-right-length 80
set -g status-right "#[fg=#a6adc8]%d/%m %H:%M #[bg=#a6e3a1,fg=#11111b,bold] #h "

# Inactive window tab
set -g window-status-format "#[fg=#6c7086] #I:#W "

# Active window tab
set -g window-status-current-format "#[bg=#313244,fg=#f5c2e7,bold] #I:#W #[default]"

# Subtle pane borders
set -g pane-border-style "fg=#313244"
set -g pane-active-border-style "fg=#89b4fa"

# Message styling
set -g message-style "bg=#313244,fg=#f5c2e7,bold"
EOF

    # 2. ~/.vimrc
    cat <<'EOF' > "${user_home}/.vimrc"
" ==============================================================================
" VIM CONFIGURATION (Modern, Clean, Ergonomic)
" ==============================================================================
set nocompatible
syntax on
filetype plugin indent on

" True color support & dark background
if has("termguicolors")
    set termguicolors
endif
set background=dark
silent! colorscheme desert

" Line numbers (hybrid relative line numbers)
set number
set relativenumber
set cursorline

" Indentation
set tabstop=4
set shiftwidth=4
set softtabstop=4
set expandtab
set autoindent
set smartindent

" Better searching
set incsearch
set hlsearch
set ignorecase
set smartcase

" UI & Ergonomics
set scrolloff=8
set sidescrolloff=8
set mouse=a
set wildmenu
set showcmd
set ruler
set backspace=indent,eol,start
set updatetime=300
set timeoutlen=500

" Clean status line
set laststatus=2
set statusline=%#PmenuSel#\ %f\ %m\ %r%h%w\ %#LineNr#%=%{&filetype}\ [%l/%L\ :\ %c]\ %p%%\ 

" Press Space to clear search highlights
nnoremap <silent> <Space> :nohlsearch<CR>
EOF

    chown "${target_user}:${target_user}" "${user_home}/.tmux.conf" "${user_home}/.vimrc"
}

configure_user_env "${ADMIN_USER}" "/home/${ADMIN_USER}"
configure_user_env "root" "/root"

echo "==> [07] Tmux and Vim configured successfully."
