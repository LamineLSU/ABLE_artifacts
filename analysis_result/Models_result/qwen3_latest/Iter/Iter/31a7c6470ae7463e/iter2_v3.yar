rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 2D 92 F6 80 74 CF }  // CMP EAX, 80F6922Dh + JE
        $pattern1 = { 8D B0 74 0C 00 00 }       // LEA ESI, [eax+00000C74h]
        $pattern2 = { 56 E8 44 09 00 00 }       // PUSH ESI + CALL (offset varies)

    condition:
        any of them
}