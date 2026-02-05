rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 85 ?? ?? ?? ?? }  // test eax, eax + jne
        $pattern1 = { 68 00 10 41 00 FF D6 }       // push + call esi (CreateThread)
        $pattern2 = { 68 88 13 00 00 FF D3 }       // push + call ebx (Sleep)

    condition:
        any of them
}