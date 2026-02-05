rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC } // CALL + TEST JE + MOV (concrete bytes)
        $pattern1 = { FF 15 AC B0 41 00 } // CALL [0041B0ACh] (concrete API check)
        $pattern2 = { 3D 00 10 00 00 0F 82 } // CMP EAX, IMM32 + JB (concrete comparison value)

    condition:
        any of them
}