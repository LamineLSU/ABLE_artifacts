rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting specific exit process calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 0xE8, 0xC8, 0xFF, 0xFF, 0xFF, 0xFF, ?? }
        $pattern1 = { 8B, ?F, ?F, ?F, F7, 50, ?? }
        $pattern2 = { E8C8FFFFFF, 55, FF7508 }

    condition:
        any of them
}