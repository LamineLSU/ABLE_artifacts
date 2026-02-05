rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 74 12 }  // CALL + TEST EAX + JE
        $pattern1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? }  // CALL + JMP (exit logic)
        $pattern2 = { 85 C0 FF 15 ?? ?? ?? ?? }  // TEST EAX + CALL (exit point)

    condition:
        any of them
}