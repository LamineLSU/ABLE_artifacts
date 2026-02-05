rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8D 95 F0 FE FF FF }  // TEST EAX, EAX + JE + LEA (specific stack offset)
        $pattern1 = { E8 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? }        // CALL + MOV ECX, ESI + CALL (variant offsets)
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }              // PUSH + POP + MOV ECX, ESI + CALL

    condition:
        any of them
}