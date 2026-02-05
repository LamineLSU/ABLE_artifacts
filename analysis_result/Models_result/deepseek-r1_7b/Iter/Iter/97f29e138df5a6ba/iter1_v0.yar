rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 20 55 FF }
        $pattern1 = { C1 E8 08 A8 01 75 10 FF }
        $pattern2 = { 90 E8 82 34 A3 04 55 FF }

    condition:
        any of them
}