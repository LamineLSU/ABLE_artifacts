rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 }  // CALL + TEST EAX sequence
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }  // CMP+JE+MOVS sequence (specific bytes)
        $pattern2 = { 3D 00 10 00 00 0F 82 }  // CMP EAX,imm32 + JB sequence

    condition:
        any of them
}