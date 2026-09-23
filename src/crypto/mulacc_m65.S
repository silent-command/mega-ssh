; The two multiply-accumulate loops that decide how long a handshake
; takes, on the 45GS02's math unit: MULTINA at $D770-$D773, MULTINB at
; $D774-$D777, the 64-bit product from $D778. Compiled C spent about 780
; cycles per 16x16 product (REQUIREMENTS.md 5.2); these loops spend
; about 130. The C in curve25519.c and poly1305.c does the same work on
; the host, and the same test vectors check both.
;
; Both routines read and write fixed buffers the C side owns, so no
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

; ---- poly_mul_m65: poly_mul_x[0..16] (32-bit each) =
;      sum over j of poly_mul_h[j] * (j <= i ? r[i-j] : 320*r[i+17-j]) ----
;
; poly_mul_h: 17 bytes. poly_mul_rr: 34 entries of 4 bytes. For column
; i the multiplier for h[j] is entry i-j+17: j <= i gives entries
; 17..33, which the C side fills with r[0..16]; j > i gives entries
; 1..16, filled with 320*r[1..16] (entry e holds 320*r[e]).

        .global poly_mul_m65
poly_mul_m65:
        lda #0
        sta $d771
        sta $d772
        sta $d773
        sta $d777
        sta kk                  ; column i
pcol:
        lda #0
        sta acc0
        sta acc1
        sta acc2
        sta acc3
        sta jj                  ; j = 0
pprod:
        ldy jj
        lda poly_mul_h,y
        sta $d770
        ; entry e = i - j + 17, times 4
        lda kk
        sec
        sbc jj
        clc
        adc #17
        asl
        asl
        tay
        lda poly_mul_rr,y
        sta $d774
        lda poly_mul_rr+1,y
        sta $d775
        lda poly_mul_rr+2,y
        sta $d776
        clc
        lda acc0
        adc $d778
        sta acc0
        lda acc1
        adc $d779
        sta acc1
        lda acc2
        adc $d77a
        sta acc2
        lda acc3
        adc $d77b
        sta acc3
        inc jj
        lda jj
        cmp #17
        bcc pprod
        ; store x[i]
        lda kk
        asl
        asl
        tay
        lda acc0
        sta poly_mul_x,y
        lda acc1
        sta poly_mul_x+1,y
        lda acc2
        sta poly_mul_x+2,y
        lda acc3
        sta poly_mul_x+3,y
        inc kk
        lda kk
        cmp #17
        bcs pcols_done
        jmp pcol
pcols_done:
        rts

        .bss
acc0:   .space 1
acc1:   .space 1
acc2:   .space 1
acc3:   .space 1
acc4:   .space 1
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
