/* Copyright 2026 Justin Cameron
 * SPDX-License-Identifier: Apache-2.0 */
; The multiply-accumulate loops that decide how long a handshake
; takes, and Poly1305's block, on the 45GS02's math unit: MULTINA at $D770-$D773, MULTINB at
; $D774-$D777, the 64-bit product from $D778. Compiled C spent about 780
; cycles per 16x16 product (REQUIREMENTS.md 5.2); these loops spend
; about 130. The C in curve25519.c and poly1305.c does the same work on
; the host, and the same test vectors check both.
;
; The routines read and write fixed buffers the C side owns, so no
; zero page is touched and the calling convention does not matter.

; The assembler gives a Q instruction on a symbol the zero-page form,
; which the linker then cannot fit; the two prefix bytes before the
; plain instruction (which it does encode absolute) are the same thing.
        .macro LDQA sym
        .byte 0x42, 0x42
        lda \sym
        .endm
        .macro STQA sym
        .byte 0x42, 0x42
        sta \sym
        .endm
        .macro ADCQA sym
        .byte 0x42, 0x42
        adc \sym
        .endm

        .text

; ---- fe_mul_m65: fe_mul_out[0..63] = fe_mul_in_a[0..31] * fe_mul_in_b[0..31]
;      (the 512-bit product, unreduced) ----
;
; The field element's 32 bytes are read as eight 32-bit limbs, which is
; the same little-endian layout the C side's sixteen 16-bit limbs have,
; so nothing changes on that side. The math unit multiplies 32 by 32,
; so a product is 64 products, not 256 (5.11). Column scanning, a
; 72-bit accumulator added with the Q instructions (LDQ/ADCQ/STQ take
; A, X, Y and Z as one 32-bit register, so the indices live in memory
; and Z is put back to zero before returning).

        .global fe_mul_m65
fe_mul_m65:
        lda #0
        ldy #11
zacc:
        sta accq,y
        dey
        bpl zacc
        sta kk                  ; k = 0
col32:
        ; i from max(0, k-7) to min(7, k); ii = 4*i, jj = 4*(k-i)
        lda kk
        sec
        sbc #7
        bcs st_ok
        lda #0
st_ok:
        sta ic
        lda kk
        cmp #7
        bcc en_ok
        lda #7
en_ok:
        sta iend
        lda kk
        sec
        sbc ic
        asl
        asl
        sta jj
        lda ic
        asl
        asl
        sta ii
p32:
        ldy ii
        lda fe_mul_in_a,y
        sta $d770
        lda fe_mul_in_a+1,y
        sta $d771
        lda fe_mul_in_a+2,y
        sta $d772
        lda fe_mul_in_a+3,y
        sta $d773
        ldy jj
        lda fe_mul_in_b,y
        sta $d774
        lda fe_mul_in_b+1,y
        sta $d775
        lda fe_mul_in_b+2,y
        sta $d776
        lda fe_mul_in_b+3,y
        sta $d777
        clc                     ; the LDQ is the settling time the product needs
        LDQA accq
        adcq $d778
        STQA accq
        LDQA accq+4
        adcq $d77c
        STQA accq+4
        bcc nc32
        inc accq+8
nc32:
        lda ii
        clc
        adc #4
        sta ii
        lda jj
        sec
        sbc #4
        sta jj
        inc ic
        lda ic
        cmp iend
        bcc p32
        beq p32
        ; emit word k, shift the accumulator down 32 bits
        lda kk
        asl
        asl
        tay
        lda accq
        sta fe_mul_out,y
        lda accq+1
        sta fe_mul_out+1,y
        lda accq+2
        sta fe_mul_out+2,y
        lda accq+3
        sta fe_mul_out+3,y
        LDQA accq+4
        STQA accq
        lda accq+8
        sta accq+4
        lda #0
        sta accq+5
        sta accq+6
        sta accq+7
        sta accq+8
        inc kk
        lda kk
        cmp #15
        bcs cols32_done
        jmp col32               ; a short branch over a jmp, never a 16-bit branch
cols32_done:
        lda accq                ; word 15: what is left
        sta fe_mul_out+60
        lda accq+1
        sta fe_mul_out+61
        lda accq+2
        sta fe_mul_out+62
        lda accq+3
        sta fe_mul_out+63
        ldz #0
        rts

; ---- poly_block_m65: one Poly1305 block on the fixed buffers ----
;
; poly_h = (poly_h + poly_m + poly_hibit * 2^128) * r, partly reduced,
; as the host's C in poly1305.c does it. h is five 32-bit limbs (20
; bytes; h[4] is below 8); poly_rr is eight: entries 1-3 are 5 r[i] / 4,
; entries 4-7 are r[0..3]. Column k of the product sums h[j] times entry
; k - j + 4, and h[4] * r[0] is a fifth column: ptab lists the 20
; products in that order, $ff ending a column, $fe the block. A column
; sum is below 2^63 (h[j] < 2^32, r[i] < 2^28), so a 64-bit accumulator
; with a guard byte carries it. The old loop did 289 products of 8 x 8
; bits per block, and the C around it 17-limb carry loops (5.21).

        .global poly_block_m65
poly_block_m65:
        clc                     ; h += m, then the 2^128 bit
        LDQA poly_h
        ADCQA poly_m
        STQA poly_h
        LDQA poly_h+4
        ADCQA poly_m+4
        STQA poly_h+4
        LDQA poly_h+8
        ADCQA poly_m+8
        STQA poly_h+8
        LDQA poly_h+12
        ADCQA poly_m+12
        STQA poly_h+12
        lda poly_h+16           ; below 8: its low byte carries it
        adc poly_hibit
        sta poly_h+16
        lda #0
        ldx #8
pz:
        sta pacc,x
        dex
        bpl pz
        sta ppos
        sta pout
pnext:
        ldy ppos
        lda ptab,y
        bmi pcol                ; $ff or $fe
        tax                     ; MULTINA = h[j]
        lda poly_h,x
        sta $d770
        lda poly_h+1,x
        sta $d771
        lda poly_h+2,x
        sta $d772
        lda poly_h+3,x
        sta $d773
        ldx ptab+1,y            ; MULTINB = its multiplier
        lda poly_rr,x
        sta $d774
        lda poly_rr+1,x
        sta $d775
        lda poly_rr+2,x
        sta $d776
        lda poly_rr+3,x
        sta $d777
        iny
        iny
        sty ppos                ; before the Q instructions take Y
        clc                     ; the LDQ is the settling time the product needs
        LDQA pacc
        adcq $d778
        STQA pacc
        LDQA pacc+4
        adcq $d77c
        STQA pacc+4
        bcc pnext_nc
        inc pacc+8
pnext_nc:
        jmp pnext               ; a short branch over a jmp, never a 16-bit branch (5.3)
pcol:
        cmp #$fe
        beq pdone
        iny
        sty ppos
        ldx pout                ; the column's word = the low 32 bits; acc >>= 32
        lda pacc
        sta ptmp,x
        lda pacc+1
        sta ptmp+1,x
        lda pacc+2
        sta ptmp+2,x
        lda pacc+3
        sta ptmp+3,x
        txa
        clc
        adc #4
        sta pout
        LDQA pacc+4
        STQA pacc
        lda pacc+8
        sta pacc+4
        lda #0
        sta pacc+5
        sta pacc+6
        sta pacc+7
        sta pacc+8
        jmp pnext
pdone:
        ; the bits from 2^130 up, times 5: c = (t4 & ~3) + (t4 >> 2)
        lda ptmp+16
        sta psh
        and #$fc
        sta pc
        lda ptmp+17
        sta psh+1
        sta pc+1
        lda ptmp+18
        sta psh+2
        sta pc+2
        lda ptmp+19
        sta psh+3
        sta pc+3
        lsr psh+3
        ror psh+2
        ror psh+1
        ror psh
        lsr psh+3
        ror psh+2
        ror psh+1
        ror psh
        clc
        LDQA pc
        ADCQA psh
        STQA pc
        clc                     ; h = t[0..3] + c, h[4] = (t4 & 3) + the carry
        LDQA ptmp
        ADCQA pc
        STQA poly_h
        LDQA ptmp+4
        ADCQA pzero
        STQA poly_h+4
        LDQA ptmp+8
        ADCQA pzero
        STQA poly_h+8
        LDQA ptmp+12
        ADCQA pzero
        STQA poly_h+12
        lda ptmp+16
        and #3
        adc #0
        sta poly_h+16
        lda #0
        sta poly_h+17
        sta poly_h+18
        sta poly_h+19
        ldz #0
        rts

        .section .rodata,"a"
ptab:
        .byte 0,16, 4,12, 8,8, 12,4, 0xff               ; h0 r0, h1 5r3/4, h2 5r2/4, h3 5r1/4
        .byte 0,20, 4,16, 8,12, 12,8, 16,4, 0xff        ; h0 r1, h1 r0, h2 5r3/4, h3 5r2/4, h4 5r1/4
        .byte 0,24, 4,20, 8,16, 12,12, 16,8, 0xff
        .byte 0,28, 4,24, 8,20, 12,16, 16,12, 0xff
        .byte 16,16, 0xff, 0xfe                          ; h4 r0, at 2^128
pzero:
        .byte 0, 0, 0, 0

        .bss
pacc:   .space 9
ptmp:   .space 20
pc:     .space 4
psh:    .space 4
ppos:   .space 1
pout:   .space 1
kk:     .space 1
ii:     .space 1
jj:     .space 1
iend:   .space 1

        .text
; ---- fe_red_m65: fe_mul_out[0..31] = fe_mul_out[0..63] mod p, reduced ----
;
; 2^256 = 38 mod p: fold the high eight limbs in, 38 * limb on the math
; unit (38 bits), then the final carry times 38 into limb 0, then
; subtract p twice where it fits. The counters that must survive an
; ADC are in X with dex/bne; the ones near a Q instruction, in memory.

        .global fe_red_m65
fe_red_m65:
        lda #38
        sta $d774
        lda #0
        sta $d775
        sta $d776
        sta $d777
        sta accq
        sta accq+1
        sta accq+2
        sta accq+3
        sta accq+4
        sta ii
fold32:
        ldy ii
        lda fe_mul_out+32,y     ; MULTINA = t[8+i]
        sta $d770
        lda fe_mul_out+33,y
        sta $d771
        lda fe_mul_out+34,y
        sta $d772
        lda fe_mul_out+35,y
        sta $d773
        clc                     ; acc += t[i]
        lda accq
        adc fe_mul_out,y
        sta accq
        lda accq+1
        adc fe_mul_out+1,y
        sta accq+1
        lda accq+2
        adc fe_mul_out+2,y
        sta accq+2
        lda accq+3
        adc fe_mul_out+3,y
        sta accq+3
        lda accq+4
        adc #0
        sta accq+4
        clc                     ; acc += 38 * t[8+i]
        LDQA accq
        adcq $d778
        STQA accq
        lda accq+4
        adc $d77c
        sta accq+4
        ldy ii                  ; limb i = the low 32 bits; acc >>= 32
        lda accq
        sta fe_mul_out,y
        lda accq+1
        sta fe_mul_out+1,y
        lda accq+2
        sta fe_mul_out+2,y
        lda accq+3
        sta fe_mul_out+3,y
        lda accq+4
        sta accq
        lda #0
        sta accq+1
        sta accq+2
        sta accq+3
        sta accq+4
        lda ii
        clc
        adc #4
        sta ii
        cmp #32
        bcs fold_done
        jmp fold32              ; 155 bytes back: a short branch over a jmp, never a 16-bit branch (5.3)
fold_done:
        ; the carry out, times 38, into limb 0 and up
        lda accq
        sta $d770
        lda #0
        sta $d771
        sta $d772
        sta $d773
        clc
        lda fe_mul_out
        adc $d778
        sta fe_mul_out
        lda fe_mul_out+1
        adc $d779
        sta fe_mul_out+1
        ldy #2
        ldx #30
prop:
        bcc prop_done
        lda fe_mul_out,y
        adc #0
        sta fe_mul_out,y
        iny
        dex
        bne prop
prop_done:
        jsr reduce_once
        jsr reduce_once
        ldz #0
        rts

; redt = fe_mul_out - p; if no borrow, fe_mul_out = redt.
; p is $FFED, fourteen $FFFF limbs, $7FFF: bytes $ED, thirty $FF, $7F.
reduce_once:
        sec
        lda fe_mul_out
        sbc #$ED
        sta redt
        ldy #1
        ldx #30
rsub:
        lda fe_mul_out,y
        sbc #$FF
        sta redt,y
        iny
        dex
        bne rsub
        lda fe_mul_out+31
        sbc #$7F
        sta redt+31
        bcc reduce_keep         ; borrow: fe_mul_out was below p
        ldx #0
rcopy:
        lda redt,x
        sta fe_mul_out,x
        inx
        cpx #32
        bne rcopy
reduce_keep:
        rts

; ---- fe_add_m65: fe_mul_out[0..15] = fe_mul_in_a + fe_mul_in_b, reduced once ----
        .global fe_add_m65
fe_add_m65:
        clc
        ldy #0
        ldx #32
addl:
        lda fe_mul_in_a,y
        adc fe_mul_in_b,y
        sta fe_mul_out,y
        iny
        dex
        bne addl
        jmp reduce_once         ; a and b are below 2^255: no carry out

; ---- fe_sub_m65: fe_mul_out[0..15] = fe_mul_in_a - fe_mul_in_b, plus p if negative ----
        .global fe_sub_m65
fe_sub_m65:
        sec
        ldy #0
        ldx #32
subl:
        lda fe_mul_in_a,y
        sbc fe_mul_in_b,y
        sta fe_mul_out,y
        iny
        dex
        bne subl
        bcs sub_done            ; no borrow
        clc
        lda fe_mul_out
        adc #$ED
        sta fe_mul_out
        ldy #1
        ldx #30
subp:
        lda fe_mul_out,y
        adc #$FF
        sta fe_mul_out,y
        iny
        dex
        bne subp
        lda fe_mul_out+31
        adc #$7F
        sta fe_mul_out+31
sub_done:
        rts

        .bss
redt:   .space 32
accq:   .space 12
ic:     .space 1
