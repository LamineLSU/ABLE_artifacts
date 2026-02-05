rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 4D F8 }
        $pattern1 = { 6A 5B 5A E8 45 FC FF }
        $pattern2 = { 8D 43 01 8B 4F FC }

    condition:
        any of them
}