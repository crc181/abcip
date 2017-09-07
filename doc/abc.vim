" Language: ABCIP
" Maintainer: Victor Roemer <vroemer@gmail.com>
" Last Change: 2012 Nov 2 

" don't do anything if user assigned syntax
if exists("b:current_syntax")
    finish
endif

" Make sure to ommit : in number check, I don't want to match 3:a=80
syn match abcNumber "\d\+:\@!" contained display
syn match abcNumber "0x\x\+:\@!" contained display
syn match abcNumber "\.\d\+" contained display
syn match abcNumber "\d\+\.\d\+" contained display

" String literals
syn match abcSpecial display contained "\\\(\\\||\|\"\)"
syn region abcString start=+L\="+ skip=+\\\\\|\\"+ end=+"+ 
    \ contained contains=abcSpecial

" ABCIP d( ... )
syn keyword abcDefineKeyword stack contained

" ABCIP c( ... )
syn keyword abcConfigKeyword contained data file reset snap seed sec
syn match abcConfigKeyword "\d\+:\w\+" contained
syn match abcConfigKeyword "\(a\|b\)\." contained

" ABCIP a( ... ) and b( ... )
syn match abcABKeyword contained "\(\d\+\:\)"
syn keyword abcABKeyword contained ack addr bos cfi cid cks code ctl data df dhw dip
syn keyword abcABKeyword contained drop dst dt ecn fill fin frag func head hops hwn
syn keyword abcABKeyword contained hwt id ihl ipn ipt jack jump key lab len lse m max
syn keyword abcABKeyword contained mf mss next off op opt pay pcp perm pid plen pro
syn keyword abcABKeyword contained psh r2 res rev rf rst segs seq shw sid sip src sre
syn keyword abcABKeyword contained syn tail tcl tid tos tot tse tsv ttl type u32 uid
syn keyword abcABKeyword contained ulen una urg vcl ver vid win wis
syn keyword abcABKeyword contained arp dst6 eth frag6 gre hop6 icmp4 icmp6
syn keyword abcABKeyword contained ip4 ip6 modbus mpls phy ppp pppoe raw rte6
syn keyword abcABKeyword contained tcp udp vlan


" Comment Magic
syn keyword abcTodo TODO FIXME XXX contained
syn region abcComment display oneline start='#' end='$'
    \ contains=abcTodo,@Spell

" ABCIP Regions
syn region abcDefinedRegion start="\<d\s*(" skip="\n" end=")"
    \ contains=abcString,abcComment,abcDefineKeyword,abcNumber fold

syn region abcConfigRegion start="\<c\s*(" skip="\n" end=")"
    \ contains=abcString,abcComment,abcConfigKeyword,abcNumber fold

syn region abcABRegion start="(" end=")"
    \ contains=abcString,abcComment,abcABKeyword,abcNumber fold

" Give it color
if version >= 508 || !exists("pfmain_syntax_init")
    if version < 508
            let pfmain_syntax_init = 1
            command -nargs=+ HiLink hi link <args>
    else
            command -nargs=+ HiLink hi def link <args>
    endif

    HiLink abcTodo Todo
    HiLink abcComment Comment
    HiLink abcSpecial Special
    HiLink abcString String
    HiLink abcNumber Number

    HiLink abcDefineKeyword Define
    HiLink abcConfigKeyword Identifier
    HiLink abcABKeyword Keyword 

    " This is an attempt to 're-sync' the syntax highlighting
    syntax sync match syncComment grouphere abcComment "#\.*$"

    delcommand HiLink
endif

let b:current_syntax = "abc"
