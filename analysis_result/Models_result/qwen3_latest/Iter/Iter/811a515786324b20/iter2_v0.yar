rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 ?? ?? ?? ?? }
        $pattern1 = { 83 F8 01 74 12 8B 45 FC }
        $pattern2 = { A1 64 B5 41 00 8B 00 FF D0 }

    condition:
        any of them
}