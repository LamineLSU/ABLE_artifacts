rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A E8 BE E8 43 }
        $pattern1 = { 8B CE 00 00 00 5B E8 CE 01 04 40 }
        $pattern2 = { E8 25 05 00 00 01 04 66 7F 00 B8 61 F8 }

    condition:
        (any of the patterns match)
}