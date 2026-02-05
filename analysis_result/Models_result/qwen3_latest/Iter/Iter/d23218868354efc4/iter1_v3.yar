rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? }
        $pattern1 = { A1 88 85 03 01 85 C0 74 ?? }
        $pattern2 = { E8 ?? ?? ?? ?? A1 88 85 03 01 }

    condition:
        any of them
}