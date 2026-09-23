; The crypto bank's trampoline at $1700, the page after mega-net's: a
; mailbox and a call entry, the same shape as mega-net's trampoline at
; $1600 (its REQUIREMENTS.md 5.10, 5.11). The client pokes the entry
; address and A/X/Y/Z, JSRs the call entry; the trampoline maps bank 1
; over $2000-$BFFF and $E000-$FFFF, calls the entry, and puts the
; caller's map back.
        .section .text,"ax",@progbits
        .global ck_tr_addr, ck_tr_a, ck_tr_x, ck_tr_y, ck_tr_z
        .global ck_tr_ra, ck_tr_rx, ck_tr_ry, ck_tr_rz
        .global ck_tr_map_a, ck_tr_map_x, ck_tr_map_y, ck_tr_map_z
        .global ck_tr_call
ck_tr_addr:  .byte 0, 0        ; $1700  entry address as mapped ($2000+3N)
ck_tr_a:     .byte 0           ; $1702
ck_tr_x:     .byte 0           ; $1703
ck_tr_y:     .byte 0           ; $1704
ck_tr_z:     .byte 0           ; $1705
ck_tr_ra:    .byte 0           ; $1706
ck_tr_rx:    .byte 0           ; $1707
ck_tr_ry:    .byte 0           ; $1708
ck_tr_rz:    .byte 0           ; $1709
ck_tr_map_a: .byte 0x00        ; $170A  the caller's MAPLO low  (A)
ck_tr_map_x: .byte 0xE0        ; $170B  the caller's MAPLO high (X)
ck_tr_map_y: .byte 0x00        ; $170C  the caller's MAPHI low  (Y)
ck_tr_map_z: .byte 0x83        ; $170D  the caller's MAPHI high (Z): $E000 -> the KERNAL
ck_tr_call:                    ; $170E
        php
        sei
        lda     #0x00           ; megabyte registers to zero first (mega-net 5.10)
        ldx     #0x0f
        ldy     #0x00
        ldz     #0x0f
        map
        ; bank 1: $2000-$7FFF from $12000 (MAPLO offset $10000, blocks 1-3),
        ; $8000-$BFFF and $E000-$FFFF from $18000/$1E000 (MAPHI offset
        ; $10000, blocks 0, 1 and 3)
        lda     #0x00
        ldx     #0xe1
        ldy     #0x00
        ldz     #0xb1
        map
        eom
        lda     ck_tr_addr
        sta     jsr_target + 1
        lda     ck_tr_addr + 1
        sta     jsr_target + 2
        lda     ck_tr_a
        ldx     ck_tr_x
        ldy     ck_tr_y
        ldz     ck_tr_z
jsr_target:
        jsr     0x0000
        sta     ck_tr_ra
        stx     ck_tr_rx
        sty     ck_tr_ry
        stz     ck_tr_rz
        lda     ck_tr_map_a
        ldx     ck_tr_map_x
        ldy     ck_tr_map_y
        ldz     ck_tr_map_z
        map
        eom
        ldz     #0x00           ; C stores zero with STZ: Z must be 0
        plp
        rts
