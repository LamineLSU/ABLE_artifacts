rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting function calls and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = {
            7412             # JZ instruction
            ??               # Offset byte
            ??               # Displacement
            E8250500h        # Address near where the jump is made
            8BCE             # CALL instruction
        }
        $pattern1 = {
            6A               # Push instruction
            ??               # Displacement for the push
            5A               # Pop instruction
            E84B1F0FEFFFFh   # Address near where the jump is made
            8BE5             # Another operation before the call
        }
        $pattern2 = {
            7407             # JE instruction (Jump if E)
            ??               # Offset byte
            74                # JZ or another conditional instruction
            FF153CE1F600h    # Address near where the jump is made
            E84B260000h     # Another operation before the call
        }

    condition:
        any of them
}