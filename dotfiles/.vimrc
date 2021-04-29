"***************************************************************
" Personal Settings
"***************************************************************
set nocompatible    " be iMproved
set modelines=0     " prevent secuirty exploits via modelines, which I never use

" Indentation settings
filetype plugin indent on
set autoindent      " Copy indent from current line when starting a new line
set cindent         " Stricter indenting rules for C files
set expandtab       " real programmers use spaces, not tabs
set shiftround
set shiftwidth=4
set smartindent     " Do smart autoindenting when starting a new line
set smarttab
set softtabstop=4
set tabstop=8       " width of normal tab character

" Search settings
set hlsearch        " Highlight search results
set ignorecase      " Ignore case when searching
set incsearch       " Incremental search; jump to match as you type
set smartcase       " Override ignorecase when search pattern has uppercase

" Display settings
silent! colorscheme onedark
set background=dark
set cursorline      " Highlight current line
set laststatus=2    " make room for custom status line
set number          " Show line numbers
set ruler           " Show line # and column at bottom
set scrolloff=3     " Set lines visible around cursor when scrolling
set showcmd         " Show command in bottom bar
set showmatch       " Show matching brackets when cursor on them
set t_Co=256        " full 256 color terminal
set wrap            " Soft-wrap lines
syntax on           " syntax highlighting

" Change cursor based on mode
let &t_SI.="\e[5 q" "SI = INSERT mode
let &t_SR.="\e[4 q" "SR = REPLACE mode
let &t_EI.="\e[1 q" "EI = NORMAL mode (ELSE)
"Cursor settings:
"  1 -> blinking block
"  2 -> solid block
"  3 -> blinking underscore
"  4 -> solid underscore
"  5 -> blinking vertical bar
"  6 -> solid vertical bar

" Editor Settings ======================================================
if has('mouse')
    set mouse=a     " Enable mouse usage (all modes)
endif
set autoread        " update automatically when a file is changed from the outside
set autowrite       " Automatically save before commands like :next and :make
set backspace=indent,eol,start  " make backspace behave like normal again
set clipboard^=unnamed,unnamedplus  " use system clipboard by default
set encoding=utf-8  " Make sure vim works with python3 files
set lazyredraw      " Don't redraw during macros (improves performance)
set hidden          " Hide buffers when they are abandoned (vs. closing them)
set history=1000    " Sets how many lines of history Vim has to remember
set nrformats-=octal    " ignore octal numbers for Ctrl-A/X (confusing)
set timeout timeoutlen=1500 ttimeoutlen=100 " Key Mapping and Keycode timeouts
set ttyfast         " fast terminal connection, helps with copy/paste
" set undofile        " create <filename>.un~ files to persist undo information
set wildmenu        " show tab-completions in command line
set wildmode=list:longest   " show all completions, sorted by longest match
command! W w !sudo tee % > /dev/null " :W to sudo-save

" Delete trailing white space on save, useful for some filetypes ;)
fun! StripTrailingWhitespace()
    let save_cursor = getpos(".")
    let old_query = getreg('/')
    silent! %s/\s\+$//e
    call setpos('.', save_cursor)
    call setreg('/', old_query)
endfun
if has("autocmd")
    autocmd BufWritePre
                \ *.php,*.cls,*.java,*.rb,*.md,*.c,*.cpp,*.cc,*.h,*.js,*.py,*.wiki,*.sh,*.coffee
                \ :call StripTrailingWhitespace()
endif

" Put these in an autocmd group, so that you can revert them with:
" `:augroup vimStartup | au! | augroup END`
augroup vimStartup
    au!
    " When editing a file, always jump to the last known cursor position.
    " Don't do it when the position is invalid, when inside an event handler
    " (happens when dropping a file on gvim) and for a commit message (it's
    " likely a different one than last time).
    autocmd BufReadPost *
                \ if line("'\"") >= 1 && line("'\"") <= line("$") && &ft !~# 'commit'
                \ |   exe "normal! g`\""
                \ | endif
    "Custom Filetype associations
    au BufNewFile,BufRead *.json    set filetype=javascript
augroup END

" Custom Keyboard commands ==============================================
let mapleader="\<space>"    " Custom <leader> key

" Quick escape from insert mode
inoremap jj <ESC>

" Fast saving
nnoremap <leader>w :w!<cr>

" Clear search highlighting
nnoremap <silent> <leader>n :nohl<cr>

" Insert blank line above cursor
nnoremap <leader><cr> m`O<esc>``

" Toggle line numbers
nnoremap <leader>1 :set number!<CR>

" Toggle relative line numbers
nnoremap <leader>0 :set relativenumber!<cr>

" Make it easy to edit the vimrc file
nnoremap <leader>ev :vsplit $MYVIMRC<cr>

" Reload vimrc file (update vim behavior based on vimrc changes)
nnoremap <leader>sv :source $MYVIMRC<cr>

" Smart way to move between windows
noremap <C-j> <C-W>j
noremap <C-k> <C-W>k
noremap <C-h> <C-W>h
noremap <C-l> <C-W>l

" Indent/unindent shortcut like vscode
nnoremap <silent> <leader>] >>
nnoremap <silent> <leader>[ <<
vnoremap <silent> <leader>] >gv
vnoremap <silent> <leader>[ <gv

" Show and switch buffers easily
nnoremap <leader>b :ls<cr>:buffer

" auto-format indentation of the current paragraph
nnoremap <leader>q gqip

" Reselect text that was just pasted, so I can perform commands on it
nnoremap <leader>v V`]

" Make tab move to matching brackets
nnoremap <tab> %
vnoremap <tab> %
