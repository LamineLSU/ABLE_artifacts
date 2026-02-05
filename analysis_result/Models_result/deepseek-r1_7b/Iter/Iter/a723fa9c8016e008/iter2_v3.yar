rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting early decision points and exit checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B 4D }
        $pattern1 = { 83 F8 01 74 6A 5B 00 00 00 5B }
        $pattern2 = { E8 E3 FA FF FF 00 02 5E 85 }

    condition:
        any of them
}