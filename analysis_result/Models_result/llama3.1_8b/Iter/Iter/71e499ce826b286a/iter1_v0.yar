rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }  // test + je (concrete bytes)
        $pattern1 = { E8 E5 FA FF FF 8B CE 83 F9 ?? ?? 03 C3 }  // call + mov (specific sequence)
        $pattern2 = { DC EC 0F 07 FC 01 00 00 00 00 }  // unique instruction sequence

    condition:
        any of them
}