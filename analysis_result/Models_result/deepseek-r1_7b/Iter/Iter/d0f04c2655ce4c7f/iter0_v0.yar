rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting stack manipulation and memory accesses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF C3 5A 4D ?? ?? 8B CE E8 74 0F 84 }
        $pattern1 = { 6A 5B 5A 8B CE E8 ?? ?? ?? FF 75 08 8B 2C 13 ?? }
        $pattern2 = { 6A 5B 5A 8B CE E8 ?? ?? FF 75 08 8B 40 AE ?? } 

    condition:
        any of them
}