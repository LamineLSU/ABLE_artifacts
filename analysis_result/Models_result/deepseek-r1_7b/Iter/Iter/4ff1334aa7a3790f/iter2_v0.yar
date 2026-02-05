rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using targeted sequences from the trace"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 4F F1 33 4A A7 A3 79 0F 52 F6 8B 8E 00 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 }
        $pattern1 = { 4F F1 33 4A A7 A3 79 0F 52 F6 8B 8E 00 00 00 00 00 00 00 0C 00 00 00 00 }
        $pattern2 = { 4F F1 33 4A A7 A3 79 0F 52 F6 8B 8E 00 00 00 00 51 FA FE B4 00 00 00 00 }

    condition:
        any of them
}