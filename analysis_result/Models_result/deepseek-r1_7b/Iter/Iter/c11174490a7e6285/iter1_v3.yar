rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting test+je sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B 45 FC }
        $pattern1 = { 85 C0 6A 5B E8 B3 03 }
        $pattern2 = { 85 C0 8B 4D F8 FF FF }

    condition:
        any of them
}