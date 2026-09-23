; The crypto bank's jump table and entry prologue: mega-net's shape
; (its src/abi/jumptable.S), with the bank's own zero page $70-$FF
; swapped in on entry and the caller's back on exit, and the bank's
; own soft stack at $BC00-$BFFF while the caller's memory is hidden.
        .section .jumptable,"ax",@progbits
        .global ck_jumptable
ck_jumptable:
        jmp     ck_entry_init           ; $2000  A=0 ok
        jmp     ck_entry_version        ; $2003  A=major X=minor
        jmp     ck_entry_sha256_init    ; $2006  A=slot
        jmp     ck_entry_sha256_update  ; $2009  A/X/Y -> {slot, ptr28, len16}
        jmp     ck_entry_sha256_final   ; $200C  A/X/Y -> {slot, out28}
        jmp     ck_entry_sha512_init    ; $200F  A=slot
        jmp     ck_entry_sha512_update  ; $2012  A/X/Y -> {slot, ptr28, len16}
        jmp     ck_entry_sha512_final   ; $2015  A/X/Y -> {slot, out28}
        jmp     ck_entry_key_set        ; $2018  A/X/Y -> {slot, key28 (32 bytes)}
        jmp     ck_entry_chacha_block   ; $201B  A/X/Y -> {keyslot, nonce8, counter u32, out28 (64 bytes)}
        jmp     ck_entry_chacha_xor     ; $201E  A/X/Y -> {keyslot, nonce8, counter u32, ptr28, len16}
        jmp     ck_entry_poly_init      ; $2021  A/X/Y -> {slot, key28 (32 bytes)}
        jmp     ck_entry_poly_update    ; $2024  A/X/Y -> {slot, ptr28, len16}
        jmp     ck_entry_poly_final     ; $2027  A/X/Y -> {slot, out28 (16 bytes)}
        jmp     ck_entry_x25519         ; $202A  A/X/Y -> {out28, scalar28, point28}; A=1
        jmp     ck_entry_x25519_base    ; $202D  A/X/Y -> {out28, scalar28}; A=1
        jmp     ck_entry_ed25519_verify ; $2030  A/X/Y -> {sig28, msg28, msglen16, pk28}; A=1 valid
        jmp     ck_entry_selftest       ; $2033  A = 0 always: the field self-test left the bank (5.22)
        jmp     ck_entry_term_init      ; $2036  A = the text colour, X = the background, Y = rows
        jmp     ck_entry_term_write     ; $2039  A/X/Y -> {src28, len16}; X = app cursor keys
        jmp     ck_entry_term_cursor    ; $203C  A = on
        jmp     ck_entry_term_end       ; $203F
        jmp     ck_entry_term_recolour  ; $2042  A = text colour, X = background
        jmp     ck_entry_ed25519_keypair ; $2045  A/X/Y -> {pk28, seed28}; A=1
        jmp     ck_entry_ed25519_sign   ; $2048  A/X/Y -> {sig28, msg28, msglen16, seed28, pk28}; A=1

        .section .noinit,"aw",@nobits
        .global ck_api_a, ck_api_x, ck_api_y, ck_api_z
        .global ck_api_ra, ck_api_rx, ck_api_ry, ck_api_rz
ck_api_a:  .skip 1
ck_api_x:  .skip 1
ck_api_y:  .skip 1
ck_api_z:  .skip 1
ck_api_ra: .skip 1
ck_api_rx: .skip 1
ck_api_ry: .skip 1
ck_api_rz: .skip 1
ck_zp_caller: .skip 0x90        ; the caller's $70-$FF while we run
ck_zp_ours:   .skip 0x90        ; our $70-$FF between calls

        .section .text,"ax",@progbits
        .macro ENTRY name, cfunc
        .global \name
\name:
        sta     ck_api_a
        stx     ck_api_x
        sty     ck_api_y
        stz     ck_api_z
        ldz     #0              ; our C stores zero with STZ: Z must be 0
        php
        sei
        jsr     ck_prologue
        jsr     \cfunc
        jmp     ck_epilogue
        .endm
        ENTRY ck_entry_init,           ck_api_init
        ENTRY ck_entry_version,        ck_api_version
        ENTRY ck_entry_sha256_init,    ck_api_sha256_init
        ENTRY ck_entry_sha256_update,  ck_api_sha256_update
        ENTRY ck_entry_sha256_final,   ck_api_sha256_final
        ENTRY ck_entry_sha512_init,    ck_api_sha512_init
        ENTRY ck_entry_sha512_update,  ck_api_sha512_update
        ENTRY ck_entry_sha512_final,   ck_api_sha512_final
        ENTRY ck_entry_key_set,        ck_api_key_set
        ENTRY ck_entry_chacha_block,   ck_api_chacha_block
        ENTRY ck_entry_chacha_xor,     ck_api_chacha_xor
        ENTRY ck_entry_poly_init,      ck_api_poly_init
        ENTRY ck_entry_poly_update,    ck_api_poly_update
        ENTRY ck_entry_poly_final,     ck_api_poly_final
        ENTRY ck_entry_x25519,         ck_api_x25519
        ENTRY ck_entry_x25519_base,    ck_api_x25519_base
        ENTRY ck_entry_ed25519_verify, ck_api_ed25519_verify
        ENTRY ck_entry_selftest,       ck_api_selftest
        ENTRY ck_entry_term_init,      ck_api_term_init
        ENTRY ck_entry_term_write,     ck_api_term_write
        ENTRY ck_entry_term_cursor,    ck_api_term_cursor
        ENTRY ck_entry_term_end,       ck_api_term_end
        ENTRY ck_entry_term_recolour,  ck_api_term_recolour
        ENTRY ck_entry_ed25519_keypair, ck_api_ed25519_keypair
        ENTRY ck_entry_ed25519_sign,   ck_api_ed25519_sign

ck_prologue:
        lda     #0x47           ; the MEGA65 I/O personality, every time
        sta     0xD02F
        lda     #0x53
        sta     0xD02F
        ldx     #0
swap_in:
        lda     $70,x
        sta     ck_zp_caller,x
        lda     ck_zp_ours,x
        sta     $70,x
        inx
        cpx     #0x90
        bne     swap_in
        lda     #0x00
        sta     __rc0
        lda     #0xC0           ; soft stack: $BC00-$BFFF, grows down
        sta     __rc1
        rts
ck_epilogue:
        ldx     #0
swap_out:
        lda     $70,x
        sta     ck_zp_ours,x
        lda     ck_zp_caller,x
        sta     $70,x
        inx
        cpx     #0x90
        bne     swap_out
        lda     ck_api_ra
        ldx     ck_api_rx
        ldy     ck_api_ry
        ldz     ck_api_rz
        plp                     ; the caller's I flag back
        rts
