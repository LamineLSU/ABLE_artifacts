rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? } // CALL TEST EAX
        $pattern1 = { 83 F8 01 ?? ?? ?? } // CMP EAX, IMM32 + JB
        $pattern2 = { 3D 00 10 00 ?? 0F 82 } // CMP EAX, IMM32 + JB

    condition:
        any of them
}