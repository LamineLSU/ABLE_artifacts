rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF 83 F8 ?? ?? 74 ?? } // CALL instruction with varying offset + TEST JE
        $pattern1 = { 3D 00 10 00 00 0F 82 ?? ?? ?? ?? 59 } // CMP EAX, IMM32 + JB (JE equivalent) + POP ECX
        $pattern2 = { FF 15 AC B0 41 00 8B CE E8 ?? ?? ?? ?? } // CALL dword ptr [0041B0ACh] + MOV ESI, EDI + CALL instruction with varying offset

    condition:
        any of them
}