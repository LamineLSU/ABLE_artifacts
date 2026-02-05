rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific calls and conditions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 40 10 8B 20 40 10 92 20 40 10 A3 20 }
        $pattern1 = { 40 10 97 20 40 10 C0 20 40 10 D6 20 }
        $pattern2 = { 40 10 A3 20 40 10 D6 20 }

    condition:
        any of them
}