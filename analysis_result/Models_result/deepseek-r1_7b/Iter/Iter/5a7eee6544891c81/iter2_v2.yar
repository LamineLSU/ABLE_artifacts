rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted conditional exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 15 FF C3 4D 87 EC B9 }
        $pattern1 = { 15 F8 C3 4D 87 EC CB 99 }
        $pattern2 = { 15 F7 C3 4D 87 ED CB 99 }

    condition:
        (any of the patterns match)
}