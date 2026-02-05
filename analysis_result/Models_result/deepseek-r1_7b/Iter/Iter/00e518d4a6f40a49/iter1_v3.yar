rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - using test followed by jump to bypass exit check"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { [8 5C 0] [7 41 2] [? ?] }
        $pattern1 = { [8 5C 0 (S EC ON D TR AC E) ] [7 41 2] [? ?] }
        $pattern2 = { [3 D 00 10 00 ] [0 0 00 00 ] [J B] }

    condition:
        any of them
}