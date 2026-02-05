rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 08 50 53 E8 EC F4 FF FF }
        $pattern1 = { 85 DB 74 1B 90 8B 45 08 }
        $pattern2 = { 75 0E 53 E8 6B F3 FF FF }

    condition:
        any of them
}