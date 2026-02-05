rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? }  // Test EAX + JE + PUSH + POP + MOV + CALL (12 bytes)
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }     // CALL + TEST EAX + JZ (12 bytes)
        $pattern2 = { B9 42 8C 19 00 50 E8 ?? ?? ?? ?? }           // MOV ECX + PUSH + CALL (12 bytes)

    condition:
        any of them
}