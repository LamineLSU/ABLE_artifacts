rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific instruction sequences from trace data"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 01 39 5E 83 }
        $pattern1 = { 5A 03 C1 01 39 5E 85 }
        $pattern2 = { ED EA EA EB 00 00 01 10 01 39 5E 85 }

    condition:
        any of them
}