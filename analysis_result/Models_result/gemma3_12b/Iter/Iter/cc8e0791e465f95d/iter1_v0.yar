rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 91 80 00 00 00 }
        $pattern1 = { 8B 45 F8 83 C0 34 50 8B 4D 08 }
        $pattern2 = { 8B 55 FC 50 8B 4D DC 51 }

    condition:
        any of them
}