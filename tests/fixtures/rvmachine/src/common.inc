# Shared tail of the machine fixtures: print a string through the legacy
# firmware console, and power off through the system reset extension.
puts:
    lbu   a0, 0(s1)
    beqz  a0, 1f
    li    a7, 1
    ecall
    addi  s1, s1, 1
    j     puts
1:  ret

shutdown:
    li    a0, 0
    li    a1, 0
    li    a6, 0
    li    a7, 0x53525354
    ecall
2:  j     2b
