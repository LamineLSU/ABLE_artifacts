rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit decision"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A E8 25 05 00 00 }
        $pattern1 = { 85 C0 74 12 6A 5B 5A E8 74 FA FF FF }
        $pattern2 = { 85 C0 74 12 6A 5B 5A FF 15 2C A1 2F 00 }
    condition:
        any of them
}