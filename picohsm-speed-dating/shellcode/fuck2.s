.arch armv7-a
.global _start

.text

_start:

.thumb
ldr r0,=#0x2000000c
ldr r0,=#0x11111111
str r3,[r0,#0]
ldr r0,=#0x20000008
str r3,[r0,#0]

// ldr r0,=#0x0800071d
ldr r0,=#0x0800072b
bx r0
