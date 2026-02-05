rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 74 10 8B FF 36 FF }
        $pattern1 = { 9A 74 0C 8D 8B FF C0 FF }
        $pattern2 = { 75 74 00 8B FF 30 FF }

    condition:
        any of them
}