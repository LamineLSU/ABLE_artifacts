rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 48 4A FF 75 08 }
        $pattern1 = { 6A 48 38 74 20 74 }
        $pattern2 = { 6A 48 36 84 C0 74 }

    condition:
        any of them
}