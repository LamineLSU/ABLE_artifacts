rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C9 FF D6 85 DB 74 12 }
        $pattern1 = { E8 ?? ?? ?? ?? FF D0 74 01 }
        $pattern2 = { 83 EC 08 89 45 FC 53 }

    condition:
        any of them
}