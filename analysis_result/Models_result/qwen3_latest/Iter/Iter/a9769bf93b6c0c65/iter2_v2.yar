rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B CE E8 ?? ?? ?? ?? }  // test+je+call sequence
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? }  // test+je+call with offset
        $pattern2 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF 03 C3 BA 04 01 00 00 }  // mov+lea+add+mov setup

    condition:
        any of them
}