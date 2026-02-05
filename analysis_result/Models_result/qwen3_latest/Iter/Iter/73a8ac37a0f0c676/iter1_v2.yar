rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }
        $pattern1 = { 50 51 52 53 FF D2 }
        $pattern2 = { A9 71 E4 55 8B 5E 5D C3 }

    condition:
        all of them
}