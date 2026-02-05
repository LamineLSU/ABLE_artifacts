rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting different instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = {
            85 C0           # TEST EAX
            0F 84 ??         # JZ (wildcard for displacement)
            ?? ?? ??         # Wildcard for additional context bytes
            8B 45 ??         # CALL (wildcard for offset)
        }

        $pattern1 = {
            E8               # E8 op
            ?? ?? ??         # Wildcard for displacement after E8
            ?? ??             # Additional wildcard bytes
            83 C4 ??         # JZ near (wildcard for displacement and opcode)
            85 C0           # CALL EAX,0F84
            0F 84 ??         # JZ (wildcard for displacement)
        }

        $pattern2 = {
            6A               # PUSH
            ?? ??             # Wildcard for displacement after PUSH
            5A               # POP Edwards
            8B CE E8          # EAX,0F84; EBP+01
            ?? ?? ??         # Wildcard for additional context bytes
            85 C0           # TEST EAX,0F84
        }

    condition:
        any of them
}