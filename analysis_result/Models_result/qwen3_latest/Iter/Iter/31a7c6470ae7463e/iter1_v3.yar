rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 2D 92 F6 80 74 CF }  // CMP EAX, 80F6922Dh followed by JE
        $pattern1 = { 52 52 8B 16 50 50 51 51 FF D2 }  // Pushes and API call sequence
        $pattern2 = { EC 8B 45 08 8B 4D 08 }  // Debug check with IN AL, DX and register moves

    condition:
        any of them
}