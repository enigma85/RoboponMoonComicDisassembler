; Common bank helpers.
MACRO ROMX_BANK
SECTION "Bank \1", ROMX[$4000], BANK[\1]
ENDM
