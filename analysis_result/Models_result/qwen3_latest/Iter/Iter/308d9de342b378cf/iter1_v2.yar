rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? } // CALL + TEST EAX + JE
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? } // PUSH + POP + MOV + CALL
        $pattern2 = { 03 C3 BA ?? ?? ?? ?? 03 C1 E8 ?? ?? ?? ?? } // ADD + MOV + ADD + CALL

    condition:
        any of them
}