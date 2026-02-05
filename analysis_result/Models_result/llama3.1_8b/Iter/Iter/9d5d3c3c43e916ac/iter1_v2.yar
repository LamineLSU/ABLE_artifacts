rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 } // CALL + TEST EAX + JE/JNE (wildcards for offsets)
        $pattern1 = { 3D 00 10 00 00 0F 82 } // CMP EAX,imm32 + JB
        $pattern2 = { 83 F8 01 74 12 8B 4D F8 } // CMP + JE + MOV (concrete bytes)

    condition:
        any of them
}