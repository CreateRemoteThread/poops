.arch armv7-a
.global _start

.text

_start:

.thumb
mov r0,sp


ldr r1,=#0x08001268
ldr r7,=#0x080004f3
bx r7
