rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? } // TEST EAX + JE (evasion check)
        $pattern1 = { 53 6A 40 53 68 40 11 33 00 } // PUSH EBX + PUSH 0x40 (exit decision)
        $pattern2 = { E8 ?? ?? ?? ?? 8B 45 FC } // CALL + MOV (indirect check)

    condition:
        any of them
}