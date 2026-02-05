rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting specific call points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 51 FF 75 08 8B 4D C3 }
        $pattern1 = { 6A 5A 8B CE E8 FF 75 08 8B 45 FF }
        $pattern2 = { 6A 5A 8B EC 8C FF 75 08 8B 4D C3 }
    condition:
        any of them
}