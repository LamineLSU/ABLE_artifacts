rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D B5 A4 FC FF FF }
        $pattern1 = { 83 C6 04 4B 75 F4 }
        $pattern2 = { 8B 85 64 F9 FF FF }

    condition:
        any of them
}